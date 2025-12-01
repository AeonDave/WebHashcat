import datetime
import itertools
from optparse import OptionParser, OptionGroup

VERSION = "0.0.3"


class PolicyGen:
    def __init__(self):
        self.output_file = None

        self.minlength = 8
        self.maxlength = 8
        self.mindigit = None
        self.minlower = None
        self.minupper = None
        self.minspecial = None
        self.maxdigit = None
        self.maxlower = None
        self.maxupper = None
        self.maxspecial = None

        # parti fisse lineari (inizio/fine)
        self.prefix = ""
        self.suffix = ""

        # parola fissa interna: posizione 1-based
        self.fixed_pos = None
        self.fixed_word = ""

        # PPS (Passwords per Second) cracking speed
        self.pps = 1_000_000_000
        self.showmasks = False

        # complessità per tipo di mask char
        self._complexity_map = {
            "l": 26,
            "u": 26,
            "d": 10,
            "s": 33,
            "a": 95,
        }

    def getcomplexity(self, mask: str) -> int:
        """Return mask complexity for the variable part (?l ?u ?d ?s ...)."""
        if not mask:
            return 1

        count = 1
        for char in mask[1:].split("?"):
            if not char:
                continue
            try:
                count *= self._complexity_map[char]
            except KeyError:
                print("[!] Error, unknown mask ?%s in mask %s" % (char, mask))
                return 0
        return count

    def _count_types(self, mask: str):
        """Count character types in a variable mask (?l ?u ?d ?s)."""
        if not mask:
            return 0, 0, 0, 0

        types = [t for t in mask[1:].split("?") if t]
        lowercount = types.count("l")
        uppercount = types.count("u")
        digitcount = types.count("d")
        specialcount = types.count("s")
        return lowercount, uppercount, digitcount, specialcount

    def _count_fixed_types(self, text: str):
        """Count character types in a fixed literal string (prefix/suffix/fixed_word)."""
        lower = upper = digit = special = 0
        for ch in text:
            if ch.islower():
                lower += 1
            elif ch.isupper():
                upper += 1
            elif ch.isdigit():
                digit += 1
            else:
                special += 1
        return lower, upper, digit, special

    def generate_masks(self, noncompliant: bool):
        """Entry point, dirama tra modalità prefix/suffix e fixed."""
        if self.fixed_pos is not None:
            return self._generate_masks_with_fixed(noncompliant)
        else:
            return self._generate_masks_with_prefix_suffix(noncompliant)

    def _generate_masks_with_prefix_suffix(self, noncompliant: bool):
        """Generazione con parti fisse solo a inizio/fine (prefix/suffix)."""

        total_count = 0
        sample_count = 0
        total_complexity = 0
        sample_complexity = 0

        charset = ['?d', '?l', '?u', '?s']

        fixed_text = self.prefix + self.suffix
        fixed_len = len(fixed_text)
        fixed_lower, fixed_upper, fixed_digit, fixed_special = self._count_fixed_types(fixed_text)

        for total_length in range(self.minlength, self.maxlength + 1):
            variable_len = total_length - fixed_len
            if variable_len < 0:
                continue

            print(
                "[*] Generating %d character password masks (variable: %d, fixed: %d)."
                % (total_length, variable_len, fixed_len)
            )

            total_length_count = 0
            sample_length_count = 0
            total_length_complexity = 0
            sample_length_complexity = 0

            for masklist in itertools.product(charset, repeat=variable_len):
                var_mask = ''.join(masklist)

                mask_complexity = self.getcomplexity(var_mask)
                if mask_complexity == 0:
                    continue

                total_length_count += 1
                total_length_complexity += mask_complexity

                var_lower, var_upper, var_digit, var_special = self._count_types(var_mask)

                lowercount = var_lower + fixed_lower
                uppercount = var_upper + fixed_upper
                digitcount = var_digit + fixed_digit
                specialcount = var_special + fixed_special

                policy_match = (
                        (self.minlower is None or lowercount >= self.minlower) and
                        (self.maxlower is None or lowercount <= self.maxlower) and
                        (self.minupper is None or uppercount >= self.minupper) and
                        (self.maxupper is None or uppercount <= self.maxupper) and
                        (self.mindigit is None or digitcount >= self.mindigit) and
                        (self.maxdigit is None or digitcount <= self.maxdigit) and
                        (self.minspecial is None or specialcount >= self.minspecial) and
                        (self.maxspecial is None or specialcount <= self.maxspecial)
                )

                selected = policy_match ^ noncompliant
                full_mask = f"{self.prefix}{var_mask}{self.suffix}"

                if selected:
                    sample_length_count += 1
                    sample_length_complexity += mask_complexity
                    if self.output_file:
                        self.output_file.write(full_mask + "\n")

                if self.showmasks:
                    mask_time = mask_complexity / self.pps if self.pps else 0
                    time_human = (
                        ">1 year"
                        if mask_time > 60 * 60 * 24 * 365
                        else str(datetime.timedelta(seconds=mask_time))
                    )
                    tag = "OK " if selected else "SKIP"
                    print(
                        "[{:>2}] {:<40} [l:{:>2} u:{:>2} d:{:>2} s:{:>2}] [{:>8}] {}".format(
                            total_length,
                            full_mask,
                            lowercount,
                            uppercount,
                            digitcount,
                            specialcount,
                            time_human,
                            tag,
                        )
                    )

            total_count += total_length_count
            sample_count += sample_length_count
            total_complexity += total_length_complexity
            sample_complexity += sample_length_complexity

        total_time = total_complexity / self.pps if self.pps else 0
        total_time_human = (
            ">1 year"
            if total_time > 60 * 60 * 24 * 365
            else str(datetime.timedelta(seconds=total_time))
        )
        print("[*] Total Masks:  %d Time: %s" % (total_count, total_time_human))

        sample_time = sample_complexity / self.pps if self.pps else 0
        sample_time_human = (
            ">1 year"
            if sample_time > 60 * 60 * 24 * 365
            else str(datetime.timedelta(seconds=sample_time))
        )
        print("[*] Policy Masks: %d Time: %s" % (sample_count, sample_time_human))

    def _generate_masks_with_fixed(self, noncompliant: bool):
        """Generazione con parola fissa interna (fixed_pos, fixed_word)
        e opzionali prefix/suffix ai bordi.
        Struttura: prefix + VAR1 + fixed_word + VAR2 + suffix
        """

        total_count = 0
        sample_count = 0
        total_complexity = 0
        sample_complexity = 0

        charset = ['?d', '?l', '?u', '?s']

        prefix_len = len(self.prefix)
        suffix_len = len(self.suffix)
        fixed_len = len(self.fixed_word)

        if self.fixed_pos is None or self.fixed_pos < 1:
            print("[!] Invalid fixed position, must be >= 1")
            return

        pref_l, pref_u, pref_d, pref_s = self._count_fixed_types(self.prefix)
        fix_l, fix_u, fix_d, fix_s = self._count_fixed_types(self.fixed_word)
        suf_l, suf_u, suf_d, suf_s = self._count_fixed_types(self.suffix)

        fixed_lower = pref_l + fix_l + suf_l
        fixed_upper = pref_u + fix_u + suf_u
        fixed_digit = pref_d + fix_d + suf_d
        fixed_special = pref_s + fix_s + suf_s

        for total_length in range(self.minlength, self.maxlength + 1):
            core_len = total_length - prefix_len - suffix_len
            if core_len < fixed_len or core_len < 0:
                continue

            fixed_pos_abs = self.fixed_pos
            fixed_pos_core = fixed_pos_abs - prefix_len  # 1-based nella parte centrale

            if fixed_pos_core < 1 or (fixed_pos_core + fixed_len - 1) > core_len:
                continue

            var1_len = fixed_pos_core - 1
            var2_len = core_len - (fixed_pos_core + fixed_len - 1)
            if var1_len < 0 or var2_len < 0:
                continue

            variable_len = var1_len + var2_len

            print(
                "[*] Generating %d character password masks "
                "(variable: %d = %d+%d, fixed: %d at abs pos %d)."
                % (total_length, variable_len, var1_len, var2_len,
                   fixed_len, fixed_pos_abs)
            )

            total_length_count = 0
            sample_length_count = 0
            total_length_complexity = 0
            sample_length_complexity = 0

            for masklist in itertools.product(charset, repeat=variable_len):
                var1_mask = ''.join(masklist[:var1_len])
                var2_mask = ''.join(masklist[var1_len:])
                var_mask = var1_mask + var2_mask

                mask_complexity = self.getcomplexity(var_mask)
                if mask_complexity == 0:
                    continue

                total_length_count += 1
                total_length_complexity += mask_complexity

                var_l, var_u, var_d, var_s = self._count_types(var_mask)

                lowercount = var_l + fixed_lower
                uppercount = var_u + fixed_upper
                digitcount = var_d + fixed_digit
                specialcount = var_s + fixed_special

                policy_match = (
                        (self.minlower is None or lowercount >= self.minlower) and
                        (self.maxlower is None or lowercount <= self.maxlower) and
                        (self.minupper is None or uppercount >= self.minupper) and
                        (self.maxupper is None or uppercount <= self.maxupper) and
                        (self.mindigit is None or digitcount >= self.mindigit) and
                        (self.maxdigit is None or digitcount <= self.maxdigit) and
                        (self.minspecial is None or specialcount >= self.minspecial) and
                        (self.maxspecial is None or specialcount <= self.maxspecial)
                )

                selected = policy_match ^ noncompliant

                full_mask = (
                        self.prefix +
                        var1_mask +
                        self.fixed_word +
                        var2_mask +
                        self.suffix
                )

                if selected:
                    sample_length_count += 1
                    sample_length_complexity += mask_complexity
                    if self.output_file:
                        self.output_file.write(full_mask + "\n")

                if self.showmasks:
                    mask_time = mask_complexity / self.pps if self.pps else 0
                    time_human = (
                        ">1 year"
                        if mask_time > 60 * 60 * 24 * 365
                        else str(datetime.timedelta(seconds=mask_time))
                    )
                    tag = "OK " if selected else "SKIP"
                    print(
                        "[{:>2}] {:<50} [l:{:>2} u:{:>2} d:{:>2} s:{:>2}] [{:>8}] {}".format(
                            total_length,
                            full_mask,
                            lowercount,
                            uppercount,
                            digitcount,
                            specialcount,
                            time_human,
                            tag,
                        )
                    )

            total_count += total_length_count
            sample_count += sample_length_count
            total_complexity += total_length_complexity
            sample_complexity += sample_length_complexity

        total_time = total_complexity / self.pps if self.pps else 0
        total_time_human = (
            ">1 year"
            if total_time > 60 * 60 * 24 * 365
            else str(datetime.timedelta(seconds=total_time))
        )
        print("[*] Total Masks:  %d Time: %s" % (total_count, total_time_human))

        sample_time = sample_complexity / self.pps if self.pps else 0
        sample_time_human = (
            ">1 year"
            if sample_time > 60 * 60 * 24 * 365
            else str(datetime.timedelta(seconds=sample_time))
        )
        print("[*] Policy Masks: %d Time: %s" % (sample_count, sample_time_human))


if __name__ == "__main__":
    header = (
            "                       _ \n"
            "     PolicyGen %s  | |\n" % VERSION +
            "      _ __   __ _  ___| | _\n"
            "     | '_ \\ / _` |/ __| |/ /\n"
            "     | |_) | (_| | (__|   < \n"
            "     | .__/ \\__,_|\\___|_|\\_\\\n"
            "     | |                    \n"
            "     |_| iphelix@thesprawl.org\n"
            "\n"
    )

    parser = OptionParser(
        "%prog [options]\n\nType --help for more options",
        version="%prog " + VERSION,
    )

    parser.add_option(
        "-o", "--outputmasks",
        dest="output_masks",
        help="Save masks to a file",
        metavar="masks.hcmask",
    )
    parser.add_option(
        "--pps",
        dest="pps",
        help="Passwords per Second",
        type="int",
        metavar="1000000000",
    )
    parser.add_option(
        "--showmasks",
        dest="showmasks",
        help="Show matching masks",
        action="store_true",
        default=False,
    )
    parser.add_option(
        "--noncompliant",
        dest="noncompliant",
        help="Generate masks for noncompliant passwords",
        action="store_true",
        default=False,
    )

    parser.add_option(
        "--prefix",
        dest="prefix",
        default="",
        help="Fixed literal prefix to prepend to each generated mask (e.g. 'amazon')",
    )
    parser.add_option(
        "--suffix",
        dest="suffix",
        default="",
        help="Fixed literal suffix to append to each generated mask",
    )
    parser.add_option(
        "--fixed",
        dest="fixed",
        nargs=2,
        metavar="POS WORD",
        help="Place fixed WORD starting at 1-based position POS in the password (e.g. --fixed 7 amazon)",
    )

    group = OptionGroup(
        parser,
        "Password Policy",
        "Define the minimum (or maximum) password strength policy that you would like to test",
    )
    group.add_option("--minlength", dest="minlength", type="int", metavar="8", default=8,
                     help="Minimum password length (including fixed prefix/suffix/word)")
    group.add_option("--maxlength", dest="maxlength", type="int", metavar="8", default=8,
                     help="Maximum password length (including fixed prefix/suffix/word)")
    group.add_option("--mindigit", dest="mindigit", type="int", metavar="1",
                     help="Minimum number of digits")
    group.add_option("--minlower", dest="minlower", type="int", metavar="1",
                     help="Minimum number of lower-case characters")
    group.add_option("--minupper", dest="minupper", type="int", metavar="1",
                     help="Minimum number of upper-case characters")
    group.add_option("--minspecial", dest="minspecial", type="int", metavar="1",
                     help="Minimum number of special characters")
    group.add_option("--maxdigit", dest="maxdigit", type="int", metavar="3",
                     help="Maximum number of digits")
    group.add_option("--maxlower", dest="maxlower", type="int", metavar="3",
                     help="Maximum number of lower-case characters")
    group.add_option("--maxupper", dest="maxupper", type="int", metavar="3",
                     help="Maximum number of upper-case characters")
    group.add_option("--maxspecial", dest="maxspecial", type="int", metavar="3",
                     help="Maximum number of special characters")
    parser.add_option_group(group)

    parser.add_option(
        "-q", "--quiet",
        action="store_true",
        dest="quiet",
        default=False,
        help="Don't show headers.",
    )

    (options, args) = parser.parse_args()

    if not options.quiet:
        print(header)

    policygen = PolicyGen()

    if options.output_masks:
        print("[*] Saving generated masks to [%s]" % options.output_masks)
        policygen.output_file = open(options.output_masks, "w", encoding="utf-8")

    if options.minlength is not None:
        policygen.minlength = options.minlength
    if options.maxlength is not None:
        policygen.maxlength = options.maxlength
    if options.mindigit is not None:
        policygen.mindigit = options.mindigit
    if options.minlower is not None:
        policygen.minlower = options.minlower
    if options.minupper is not None:
        policygen.minupper = options.minupper
    if options.minspecial is not None:
        policygen.minspecial = options.minspecial
    if options.maxdigit is not None:
        policygen.maxdigit = options.maxdigit
    if options.maxlower is not None:
        policygen.maxlower = options.maxlower
    if options.maxupper is not None:
        policygen.maxupper = options.maxupper
    if options.maxspecial is not None:
        policygen.maxspecial = options.maxspecial

    policygen.prefix = options.prefix or ""
    policygen.suffix = options.suffix or ""

    if options.fixed:
        pos_str, word = options.fixed
        try:
            pos = int(pos_str)
            if pos < 1:
                raise ValueError
        except ValueError:
            parser.error("--fixed POS WORD requires POS to be an integer >= 1")

        policygen.fixed_pos = pos
        policygen.fixed_word = word

    if options.pps:
        policygen.pps = options.pps
    if options.showmasks:
        policygen.showmasks = options.showmasks

    print("[*] Using {:,d} keys/sec for calculations.".format(policygen.pps))

    print("[*] Password policy:")
    print(
        "    Pass Lengths: min:%d max:%d"
        % (policygen.minlength, policygen.maxlength)
    )
    print(
        "    Min strength: l:%s u:%s d:%s s:%s"
        % (
            policygen.minlower,
            policygen.minupper,
            policygen.mindigit,
            policygen.minspecial,
        )
    )
    print(
        "    Max strength: l:%s u:%s d:%s s:%s"
        % (
            policygen.maxlower,
            policygen.maxupper,
            policygen.maxdigit,
            policygen.maxspecial,
        )
    )
    if policygen.fixed_pos is not None:
        print(
            "    Fixed word: '%s' at position %d (1-based)"
            % (policygen.fixed_word, policygen.fixed_pos)
        )
    if policygen.prefix or policygen.suffix:
        print(
            "    Fixed parts: prefix='%s' suffix='%s'"
            % (policygen.prefix, policygen.suffix)
        )

    print(
        "[*] Generating [%s] masks."
        % ("compliant" if not options.noncompliant else "non-compliant")
    )
    policygen.generate_masks(options.noncompliant)

    if policygen.output_file:
        policygen.output_file.close()
