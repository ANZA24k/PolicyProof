"""Prepare an evidence commitment without a wallet or private key.

Usage: python scripts/prepare_bundle.py POLICY_JSON ID SUBJECT PERIOD SOURCE_URL SOURCE_FILE OUTPUT
Upload OUTPUT to a public commit-pinned GitHub location before submitting its hash.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 8:
        raise SystemExit(__doc__)
    policy_file, identifier, subject, period, source_url, source_file, output = sys.argv[1:]
    if not re.fullmatch(r'https://raw\.githubusercontent\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+\.(json|md|txt)', source_url):
        raise SystemExit('Source URL must be pinned to a complete Git commit.')
    if any(part in ['', '.', '..'] for part in source_url[len('https://raw.githubusercontent.com/'):].split('/')):
        raise SystemExit('Invalid source path.')
    source = Path(source_file).read_bytes()
    if len(source) > 16000:
        raise SystemExit('Source exceeds 16,000 bytes.')
    source.decode('utf-8')
    policy = json.loads(Path(policy_file).read_text())
    canonical = json.dumps(policy, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    bundle = {'schema':'policyproof/v1', 'synthetic':False, 'assessment_id':identifier, 'policy_sha256':hashlib.sha256(canonical.encode()).hexdigest(), 'subject':subject, 'period':period, 'sources':[{'url':source_url,'sha256':hashlib.sha256(source).hexdigest()}]}
    raw = (json.dumps(bundle, indent=2)+'\n').encode()
    if len(raw)>16000:
        raise SystemExit('Bundle exceeds 16,000 bytes.')
    Path(output).write_bytes(raw)
    print('Bundle SHA-256:', hashlib.sha256(raw).hexdigest())
    print('Policy SHA-256:', bundle['policy_sha256'])
    print('Verify that the published source URL serves the exact local source bytes before submitting.')

if __name__ == '__main__':
    main()
