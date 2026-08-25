# External Vault Data — Staging Area

Temporary staging area for merging a vault from another machine. All `*.db`, `*.bin`, and `*.enc` files here are gitignored — only this README is tracked.

## Recommended: encrypted export (single file, no salt mismatch)

On the other machine:

```bash
python3 scripts/vault.py export --out /tmp/vault.enc
```

Copy `/tmp/vault.enc` here, then on this machine:

```bash
cp /path/to/vault.enc data/from-other/vault.enc
python3 scripts/vault.py import --in data/from-other/vault.enc --mode merge
python3 scripts/vault.py verify
rm data/from-other/vault.enc
```

`--mode merge` upserts (default). Use `--mode replace` to wipe local before import. The blob is Fernet-encrypted with your master key (`0600`) — same key is required to import.

## Legacy: raw database + salt

If you have `vault.db` + `salt.bin` directly:

```bash
cp /path/from-other/vault.db data/from-other/vault.db
cp /path/from-other/salt.bin data/from-other/salt.bin
python3 scripts/combine_vaults.py
python3 scripts/vault.py verify
rm data/from-other/vault.db data/from-other/salt.bin
```

Copy both files together — losing the salt makes passwords undecryptable. The combiner re-encrypts entries with the local salt. Copy the merged `data/vault.db` + `data/salt.bin` back to the other machine to converge.

## Important

- Never commit `vault.db`, `salt.bin`, or `*.enc` — they are excluded by `.gitignore`.
- Keep file permissions `0600` and delete staging files after a successful `verify`.
- Back up `data/vault.db` + `data/salt.bin` together before any merge or replace.
