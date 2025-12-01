# Guide to Using D(istributed)Hashcat

Tip: a dictionary attack + multiple rulesets usually gives better efficiency than complex masks, especially for human passwords.
The dictionary should be specific to the target, while rules should be chained and simple.

---

## 1) Uploading wordlists, rules, and masks

- Go to: Hashcat -> Files
- Available tabs: Wordlists, Rules, Masks
  - Wordlists: upload `.txt`/`.list`/`.wordlist` files, or compressed `.zip`/`.gz` (used directly by hashcat without extraction).
  - Rules: upload hashcat rule files (extension `.rule`).
  - Masks: upload mask files (`.hcmask` or `.txt` with one mask per line). Empty lines or lines starting with `"#"` are ignored.
- The system maintains a metadata cache (line counts, paths) to speed up listing after the first upload.

Masks from the generator:
- Go to: Hashcat -> Mask generator
- Set the constraints (min/max lengths, character classes, prefix/suffix, fixed position, pps, etc.) and click Generate.
- Copy the output into a local file with extension `.hcmask` (or `.txt`) and then upload it under Files -> Masks.

Note: the uploaded file name is what you will select later when configuring sessions.

---

## 2) Adding nodes and synchronizing

- Go to: Nodes
- Add one or more nodes by providing hostname, port (default 9999), and the node's credentials.
- Open the node's detail page and click Synchronise to propagate:
  - Wordlists, Rules, Masks
  - Metadata about hash types and device capabilities (CPU/GPU)
  - If you don't propagate these files, you won't be able to use them in sessions.

Brain (optional):
- If you want to use hashcat Brain to coordinate multiple nodes on the same attack, enable it in the node configuration (variables in the shared `.env` file). WebHashcat automatically detects whether the node has Brain enabled.
- Synchronisation by itself does not enable Brain: nodes must already be started with the correct Brain parameters.
- Nodes auto-configure themselves to use Brain when you select "Brain cluster" during session creation.

---

## 3) Adding hashes and creating sessions

Hash import:
- Go to: Hashcat -> Hashes, then click "Add".
- Choose the hash type (hashcat ID) that matches your hashes.
- Give a name to the set.
- Paste the hashes into the "Hashes" field or upload a file. Tick "Username included (user:hash)" if lines are in `user:hash` format.

Heterogeneous hashes and targeted sessions:
- You can upload or import a file that contains heterogeneous hashes. Each session selects a single "hash type" (`-m`) and works only on compatible lines; the others remain for subsequent sessions with the correct type.

Creating one or more sessions on the same hashfile:
- In the Hashfiles table, use the "+" button to open "New session". Two tabs:
  1) Dictionary: select a Wordlist and (optionally) one or more Rules (applied in order).
  2) Mask: select a Mask from the uploaded catalog.
- Node/cluster choice:
  - Specific node: runs everything on that worker.
  - Brain cluster: creates one session per node with Brain enabled; clients coordinate via Brain to avoid duplicates. DOES NOT WORK ON FAST HASHES (typically on hashes with id < 1000).
  - Distributed split: divides the keyspace across available nodes using weights based on capabilities (e.g. GPU > CPU) and assigns each one a distinct portion (skip/limit). It does not use Brain but requires nodes with Brain enabled (as indicated in the UI: "all Brain-enabled nodes, no Brain").
- Options: end date/time (optional), saving debug files, "kernel optimization" (`-O`, faster but with password length limits imposed by hashcat).

Practical tips:
- After uploading new wordlists/rules/masks, synchronise nodes before starting sessions that use them.
- If a session doesn't start, check node status (Nodes -> info), presence of the assets, and, if using clusters, the Brain configuration.

---

## 4) "Attack guide": recommended strategy (dict/mask)

Progressive approach to maximize results and time.

1) First pass: large dictionaries with almost no rules
- Example: large generic wordlists (weakpass4, hashkiller, extended rockyou2021, leak compilations), with zero or very few rules.
- Goal: quickly catch the most common passwords without exploding the keyspace.

2) Second pass: specific dictionaries + comprehensive rules
- Targeted dictionaries (names, surnames, vocabulary, usernames, internal lists) combined with already-prepared "heavy" rulesets.
- Goal: increase coverage while staying relevant to the target/context.

3) Third pass: small/specific/generated dictionaries + concatenation of micro-rules
- Start from highly targeted or generated wordlists (OSINT, known conventions) and chain rules that perform micro-transformations:
  - digit_append (append digits),
  - digit_prepend (prepend digits),
  - simple_case (simple upper/lowercase variations),
  - transform (basic substitutions),
  - reverse (reverse),
  - leet (leet alphabet),
  combined in cascade.
- Result: a large number of variants, but context-driven, with good efficiency.

4) Final pass: specific masks (even from known words)
- Use masks that reflect policies/habits: fixed length, initial capital letter, trailing digits, required symbol, etc.
- The Mask generator (Hashcat -> Mask generator) helps you build consistent sets with min/max constraints and prefix/suffix; you can also start from known words using prefix/suffix; save the output as `.hcmask` and upload it in Files -> Masks.

Load distribution: Brain cluster vs Distributed split
- Brain cluster: ideal when multiple nodes attack the same keyspace/attack. Brain avoids duplicate work. For "fast" hashes the system automatically uses a lighter Brain mode; for "slow" hashes a more complete mode.
- Distributed split: useful to deterministically split the keyspace across nodes without Brain. The split uses weights based on node capabilities (e.g. GPUs with higher weight than CPUs) and assigns skip/limit portions.

Monitoring results and iterating
- Monitor status and results in the Hashes page; download cracked hashes/potfile as needed.
- Based on the results, move to the next step or refine masks and rules.

---

## FAQ

- Can I mix different hash types in the same file?
  Yes, but each session uses a single "hash type" (`-m`). Incompatible lines remain pending for sessions with the correct type.

- How do I propagate assets to nodes?
  After uploading them in Files, go to Nodes and use Synchronise on active nodes.

- Is Brain mandatory for multi-node?
  No. "Distributed split" divides the work without Brain. With Brain, instead, nodes automatically avoid duplication on the same attack.

- Do compressed wordlists work?
  Yes: `.zip` and `.gz` are supported and used directly. Other compression types are not supported.
