"""Scan a local directory for private key markers and suspicious credential assignments, with redacted findings."""
import argparse
import json
from pathlib import Path
import re

SKIP = {'.git', '.venv', 'venv', '__pycache__', 'node_modules'}
ASSIGNMENT = re.compile(r"""\b(password|api_key|access_token|secret)\s*[:=]\s*["']([^"'\r\n]{8,})["']""", re.I)
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')

def scan(root, max_bytes=1048576):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or max_bytes < 1:
        raise ValueError('directory and positive max_bytes required')
    findings, skipped = [], []
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in SKIP for part in relative.parts) or path.is_symlink() or not path.is_file():
            continue
        path.resolve().relative_to(root)
        if path.stat().st_size > max_bytes:
            skipped.append({'path':relative.as_posix(),'reason':'size_limit'})
            continue
        raw = path.read_bytes()
        try:
            if b'\x00' in raw:
                raise UnicodeError()
            text = raw.decode('utf-8')
        except UnicodeError:
            skipped.append({'path':relative.as_posix(),'reason':'binary_or_encoding'})
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if PRIVATE_KEY.search(line):
                findings.append(dict(path=relative.as_posix(),line=number,rule='private_key_marker',value='[REDACTED]'))
            for match in ASSIGNMENT.finditer(line):
                findings.append(dict(path=relative.as_posix(),line=number,rule=match[1].lower(),value='[REDACTED]'))
    return dict(findings=findings, skipped=skipped)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    try:
        report = scan(args.root)
        print(json.dumps(report, indent=2))
        return int(bool(report['findings']))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'error: {exc}\n')

if __name__ == '__main__':
    raise SystemExit(main())
