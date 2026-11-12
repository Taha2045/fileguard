#!/usr/bin/env python3
"""FileGuard - file integrity monitoring (FIM) with tamper-evident baselines.

  fileguard init  <dir> -b baseline.json     create a SHA-256 baseline
  fileguard check <dir> -b baseline.json     report added / modified / deleted / permission changes

If the FILEGUARD_KEY environment variable is set, the baseline is signed with HMAC-SHA256, so an
attacker who edits both a file *and* the baseline is detected.

Exit codes: 0 = clean, 1 = changes detected, 2 = error or baseline tampering.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
CHUNK = 1024 * 1024


class BaselineError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p) for p in patterns)


def scan(root: Path, exclude: list[str] | None = None) -> dict[str, dict]:
    """Return {relative_path: {sha256, size, mode}} for every file under root (symlinks are not followed)."""
    exclude = exclude or []
    result: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if _excluded(rel, exclude):
                continue
            try:
                st = full.lstat()
                if stat.S_ISLNK(st.st_mode):
                    digest = hashlib.sha256(os.readlink(full).encode()).hexdigest()
                elif stat.S_ISREG(st.st_mode):
                    digest = sha256_file(full)
                else:
                    continue
            except OSError as e:
                print(f"warning: cannot read {rel}: {e}", file=sys.stderr)
                continue
            result[rel] = {"sha256": digest, "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode))}
    return result


def _sign(files: dict, key: str) -> str:
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()


def create_baseline(root: Path, exclude: list[str] | None = None, key: str | None = None) -> dict:
    files = scan(root, exclude)
    baseline = {
        "version": VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(root.resolve()),
        "exclude": exclude or [],
        "files": files,
    }
    if key:
        baseline["hmac"] = _sign(files, key)
    return baseline


def verify_baseline(baseline: dict, key: str | None) -> None:
    """Raise BaselineError if the baseline signature is missing/invalid."""
    if "files" not in baseline:
        raise BaselineError("baseline file is malformed")
    if key:
        expected = baseline.get("hmac")
        if not expected:
            raise BaselineError("baseline is not signed but FILEGUARD_KEY is set")
        if not hmac.compare_digest(expected, _sign(baseline["files"], key)):
            raise BaselineError("BASELINE TAMPERED OR WRONG KEY - HMAC mismatch")
    elif "hmac" in baseline:
        print("warning: baseline is signed but FILEGUARD_KEY is not set; signature not verified", file=sys.stderr)


def compare(old: dict[str, dict], new: dict[str, dict]) -> dict[str, list]:
    added = sorted(set(new) - set(old))
    deleted = sorted(set(old) - set(new))
    modified, perms = [], []
    for path in sorted(set(old) & set(new)):
        if old[path]["sha256"] != new[path]["sha256"]:
            modified.append(path)
        elif old[path]["mode"] != new[path]["mode"]:
            perms.append((path, old[path]["mode"], new[path]["mode"]))
    return {"added": added, "deleted": deleted, "modified": modified, "permissions": perms}


def format_report(changes: dict) -> str:
    total = sum(len(v) for v in changes.values())
    if total == 0:
        return "OK - no changes detected."
    lines = [f"ALERT - {total} change(s) detected", ""]
    for label, key in [("MODIFIED", "modified"), ("ADDED", "added"), ("DELETED", "deleted")]:
        for p in changes[key]:
            lines.append(f"  [{label:<8}] {p}")
    for p, a, b in changes["permissions"]:
        lines.append(f"  [PERMS   ] {p}  {a} -> {b}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fileguard", description="File integrity monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "check"):
        sp = sub.add_parser(name)
        sp.add_argument("directory", type=Path)
        sp.add_argument("-b", "--baseline", type=Path, default=Path("baseline.json"))
        sp.add_argument("-x", "--exclude", action="append", default=[], help="glob to ignore (repeatable)")
    sub.choices["check"].add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    key = os.environ.get("FILEGUARD_KEY") or None
    if not args.directory.is_dir():
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2

    if args.cmd == "init":
        b = create_baseline(args.directory, args.exclude, key)
        args.baseline.write_text(json.dumps(b, indent=2), encoding="utf-8")
        print(f"Baseline created: {len(b['files'])} files -> {args.baseline}"
              f"{' (HMAC-signed)' if key else ' (UNSIGNED - set FILEGUARD_KEY to sign)'}")
        return 0

    try:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        verify_baseline(baseline, key)
    except (OSError, json.JSONDecodeError, BaselineError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    exclude = args.exclude or baseline.get("exclude", [])
    changes = compare(baseline["files"], scan(args.directory, exclude))
    if args.json:
        print(json.dumps({**changes, "permissions": [list(p) for p in changes["permissions"]]}, indent=2))
    else:
        print(format_report(changes))
    return 1 if any(changes.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
