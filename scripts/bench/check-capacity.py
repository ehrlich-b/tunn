#!/usr/bin/env python3
"""Replay the capacity acceptance on fresh, external work/evidence directories."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('measure', 'self-test'))
    p.add_argument('--work-root', type=Path, required=True)
    p.add_argument('--output-root', type=Path, required=True)
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[2]
    for root in (args.work_root, args.output_root):
        root = root.resolve()
        check(root != repo and repo not in root.parents, 'use external work and evidence')
        root.mkdir(parents=True, exist_ok=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()

    def execute(label, switches, expected):
        work = Path(tempfile.mkdtemp(prefix=label+'-', dir=args.work_root.resolve()))
        output = Path(tempfile.mkdtemp(prefix=label+'-', dir=args.output_root.resolve()))
        command = ['nice', '-n', '10', sys.executable, str(Path(__file__).with_name('relay-bench.py')),
                   '--capacity', '--work-dir', str(work), '--output', str(output)] + switches
        with (output / 'invocation.log').open('w') as log:
            print('+ ' + ' '.join(command), flush=True)
            result = subprocess.run(command, cwd=repo, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=2700, env=dict(os.environ, BROWSER='false'))
        data = json.loads((output / 'capacity.json').read_text())
        print(json.dumps({'output': str(output), 'exit_code': result.returncode,
                          'first_failure': data['first_failure'], 'elapsed_seconds': data['elapsed_seconds'],
                          'timing_warnings': [r['timing_warning'] for r in data['steps'] if r.get('timing_warning')]}), flush=True)
        check(result.returncode == expected, f'{label}: expected exit {expected}, got {result.returncode}; see {output}')
        check(data['head'] == head and data['niceness'] >= 10, 'wrong HEAD or niceness')
        check(data['relay_affinity_observed'] == data['relay_affinity'] and data['relay_niceness'] >= 10, 'taskset/niceness not applied to relay')
        check(data['cpus'] == 1 and len(data['relay_affinity']) == 1 and data['gomemlimit'] == '400MiB', 'wrong relay shape')
        check(data['elapsed_seconds'] < 2700 and not data.get('harness_error'), 'harness failed or exceeded runtime')
        check(data['rss_budget_mib'] == 512, 'wrong RSS budget')
        check(data['database']['journal_mode'] == 'wal' and data['database']['synchronous'] == 2, 'production SQLite durability required')
        check(data['database']['owners'] == (6 if data['self_test'] else 1000), 'missing fixture accounts')
        check(set(data['relay_affinity']).isdisjoint(data['other_affinity']), 'load shares relay core')
        check(all('generator' not in (r['failure'] or '') for r in data['steps']), 'generator-limited measurement')
        check(all(r['rss_peak_mib'] > 0 for r in data['steps']), 'missing RSS measurement')
        for row in data['steps']:
            state = row['registration']
            count = row['target'] if row['stage'] == 'idle' else data['traffic_tunnels']
            check(state['tunnels'] == state['account_backed'] == state['shared'] == count, 'account/sharing registration bypass')
            check(state['quota_exempt'] == 0 and state['metering'] and state['account_plans'], 'account admission/ledger bypass')
            if row['stage'] != 'traffic':
                continue
            usage = row['ledger_export']['owner_usage']
            check(usage.get('admitted_requests', 0) > 0, 'visitor admissions absent from owner ledger')
            if not data['forced_failure'] and row['failure'] is None:
                check(usage.get('total_bytes', 0) > 0, 'visitor bytes absent from owner ledger')
            load = row['load']
            check(load['traffic']['count'] == row['target'] * data['step_seconds'], 'missing offered arrivals')
            for key in ('traffic', 'login', 'account'):
                check(load[key]['count'] > 0 and load[key]['p99_ms'] > 0, 'missing latency/page probes')
            with gzip.open(output / f"traffic-{row['target']}.json.gz", 'rt') as f:
                samples = json.load(f)
            check(len(samples) == load['traffic']['count'], 'raw observations missing')
            check(sum(bool(s.get('error')) for s in samples) == load['traffic']['errors'], 'error count mismatch')
        report = (output / 'CAPACITY.md').read_text()
        check(report.splitlines()[-1].startswith('Recommendation:'), 'report must end with a plain recommendation')
        return output, data

    if args.mode == 'measure':
        output, data = execute('measure', [], 0)
        check([r['target'] for r in data['steps'] if r['stage'] == 'idle'] == [10, 50, 100, 200, 400, 600, 800, 1000], 'incomplete idle ramp')
        check([r['target'] for r in data['steps'] if r['stage'] == 'traffic'][:8] == [10, 50, 100, 200, 400, 600, 800, 1000], 'incomplete visitor ramp')
        check(data['traffic_tunnels'] == 20 and data['step_seconds'] == 15, 'wrong workload')
        for name in ('CAPACITY.md', 'capacity.json'):
            shutil.copyfile(output / name, args.output_root / name)
        (args.output_root / 'measurement-path.txt').write_text(str(output.resolve()) + '\n')
    else:
        _, good = execute('tiny', ['--capacity-self-test'], 0)
        check(good['first_failure'] is None, 'tiny ramp failed')
        attempts = sum((r['load']['traffic']['count'] + good['traffic_tunnels'] - 1) // good['traffic_tunnels'] for r in good['steps'] if r['stage'] == 'traffic')
        usage = good['steps'][-1]['ledger_export']['owner_usage']
        check(usage['admitted_requests'] == attempts and usage['total_bytes'] == attempts * good['body_bytes'], 'tiny owner ledger must match successful traffic exactly')
        _, bad = execute('forced', ['--capacity-self-test', '--capacity-force-failure'], 1)
        check(bad['first_failure'] is not None and bad['first_failure']['mode'] == 'errors', 'forced HTTP failure was not identified')
        check(any(r.get('load', {}).get('traffic', {}).get('errors', 0) for r in bad['steps']), 'forced error disappeared')
        measured = args.output_root.parent / 'capacity.json'
        measured_seconds = json.loads(measured.read_text())['elapsed_seconds'] if measured.exists() else 0
        check(measured_seconds + good['elapsed_seconds'] + bad['elapsed_seconds'] < 2700, 'measurement and self-tests exceeded runtime budget')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'capacity-check: {exc}', file=sys.stderr)
        sys.exit(1)
