# External Vault Data

This folder is used as a staging area to hold `vault.db` and `salt.bin` from other machines before combining them into the local vault.

To combine databases, place the external `vault.db` and `salt.bin` here, then run the `combine_vaults.py` script.

**Important**: Do not commit actual `vault.db` or `salt.bin` files to version control.
