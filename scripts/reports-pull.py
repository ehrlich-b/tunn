#!/usr/bin/env python3
"""Pull new reports into a local append-only inbox."""
import argparse
import json
import os
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inbox', default=str(Path('/work') / 'lanes' / 'tunn-reports' / 'inbox.jsonl'))
    parser.add_argument('--url', default='https://tunn.to/ops/reports')
    parser.add_argument('--token-file', default=str(Path.home() / '.config/forge-keys/tunn-reports.env'))
    args = parser.parse_args()
    token = ''
    for line in Path(args.token_file).read_text().splitlines():
        if line.startswith('TUNN_REPORTS_TOKEN='):
            token = line.split('=', 1)[1].strip().strip('"\'')
    if not token:
        raise ValueError('missing TUNN_REPORTS_TOKEN')
    inbox = Path(args.inbox)
    inbox.parent.mkdir(parents=True, exist_ok=True)
    # The inbox itself is the checkpoint: a failed fetch cannot advance it.
    last = 0
    if inbox.exists():
        with inbox.open() as f:
            for line in f:
                last = max(last, int(json.loads(line)['id']))
    while True:
        req = urllib.request.Request(args.url + '?since=' + str(last), headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(req, timeout=30) as response:
            reports = json.load(response)
        if not reports:
            break
        previous = last
        with inbox.open('a') as f:
            for report in reports:
                if int(report['id']) > last:
                    f.write(json.dumps(report, ensure_ascii=True) + '\n')
                    f.flush()
                    os.fsync(f.fileno())
                    last = int(report['id'])
        if last == previous:
            raise ValueError('report page did not advance')

if __name__ == '__main__':
    main()
