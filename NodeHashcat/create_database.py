#!/usr/bin/python3

from hashcat import Session

# Ensure table exists without dropping existing data
Session.create_table(safe=True)
