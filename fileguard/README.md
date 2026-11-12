# 🔍 FileGuard

![CI](https://github.com/Taha2045/fileguard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**File Integrity Monitoring (FIM)** in a single dependency-free Python file. It records a SHA-256
baseline of a directory and later reports exactly what was **modified, added, deleted** or had its
**permissions changed** - the core control behind PCI-DSS 11.5 and many EDR/FIM products.

**Tamper-evident baselines:** with `FILEGUARD_KEY` set, the baseline is signed with HMAC-SHA256.
An attacker who alters a binary *and* rewrites the baseline to hide it is still caught.

Relevant ATT&CK techniques: T1565 (Data Manipulation), T1070 (Indicator Removal), T1543 (Create/Modify System Process), T1036 (Masquerading).

## Usage

```bash
export FILEGUARD_KEY="a-long-random-secret"        # optional but recommended

python fileguard.py init  /etc -b etc.baseline.json -x "*.log" -x "*.cache"
python fileguard.py check /etc -b etc.baseline.json
python fileguard.py check /etc -b etc.baseline.json --json     # for SIEM ingestion
```

```
ALERT - 3 change(s) detected

  [MODIFIED] ssh/sshd_config
  [ADDED   ] cron.d/.hidden_job
  [PERMS   ] shadow  0o640 -> 0o666
```

| Exit code | Meaning |
|---|---|
| 0 | No changes |
| 1 | Changes detected |
| 2 | Error, or **baseline tampering / wrong key** |

Run it from cron or a systemd timer and alert on a non-zero exit code.

## Design decisions

- SHA-256 hashed in 1 MB chunks (constant memory on large files).
- Symlinks are **not followed** (their target string is hashed) - prevents escaping the monitored tree.
- Constant-time HMAC comparison (`hmac.compare_digest`).
- The key is read from the environment, never stored in the baseline.

## Limitations

- Detection is **periodic**, not real-time (no inotify/ETW hook). Store the baseline on read-only or remote media; a
  root-level attacker who also steals the HMAC key can forge it.
- Does not track extended attributes, ownership or ACLs.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## License

MIT
