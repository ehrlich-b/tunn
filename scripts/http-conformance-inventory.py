#!/usr/bin/env python3
"""Report executed response cells; missing/zero/failed gates never mean PASS."""
import argparse
import json
from pathlib import Path
import sys

# Package + function prefix + independently expected number of leaf cases.
SUPPORTED = [
    ('sdk', 'TestHTTPFidelitySDKConformance', 26),
    ('internal/host', 'TestHTTPFidelityRelayConformance', 26),
    ('internal/host', 'TestHTTPFidelityUploadFailureAbortsResponse', 1),
    ('internal/host', 'TestHTTPFidelityWireUploadEOFAbortsResponse', 1),
    ('sdk', 'TestHTTPFidelityReconnectNegotiation', 2),
    ('sdk', 'TestHTTPFidelityRequestsSpanReconnect', 1),
    ('internal/host', 'TestHTTPFidelityUploadTerminalSchedules', 4),
    ('internal/host', 'TestHTTPFidelityCancellationAfterPrefix', 3),
    ('sdk', 'TestHTTPFidelitySDKContentLengths', 8),
    ('internal/host', 'TestHTTPFidelityConsumerContentLengths', 8),
    ('sdk', 'TestHTTPFidelityControllerWrapper', 2),
    ('sdk', 'TestHTTPFidelityReadDeadline', 1),
    ('sdk', 'TestHTTPFidelityWriteDeadline', 1),
    ('sdk', 'TestHTTPFidelityCompletedBodyLateTerminal', 3),
    ('sdk', 'TestHTTPFidelityFlushedPrefix', 1),
    ('pkg/proto/tunnelv1', 'TestHTTPFidelityWireVersions', 2),
    ('pkg/proto/tunnelv1', 'TestHTTPFidelityLegacyTerminalFrame', 1),
]
UNSUPPORTED = [
    ('sdk', 'TestHTTPFidelityInformationalLimit', 2, '1xx is consumed upstream; only final metadata is serialized'),
    ('sdk', 'TestHTTPFidelityUnsupportedUpgrade', 2, 'Generic HTTP 101 requires the dedicated WebSocket transport'),
    ('sdk', 'TestHTTPFidelityOpaqueWrapperUnsupported', 1, 'ResponseController cannot discover capabilities hidden by a wrapper without Unwrap'),
    ('sdk', 'TestHTTPFidelityLegacyHeaderLoss', 2, 'Legacy maps comma-join repeated fields; exact multiplicity is unavailable'),
    ('internal/host', 'TestHTTPFidelityLegacyCookieAmbiguity', 1, 'Legacy cookie splitting cannot recover all comma-containing values'),
]
REQUIRED_UNRUN = [
    {'gate': 'make -j1 test-sdk-contract', 'cells': 8, 'test': 'TestSDKResponseConformance', 'reason': 'Exported PublishHandler requires a disposable loopback relay'},
    {'gate': 'make -j1 test-sdk-contract', 'cells': 1, 'test': 'TestSDKResponseControllerConformance', 'reason': 'Exported-handler relay runtime requires ordinary-host loopback'},
    {'gate': 'make -j1 test-sdk-response-consumer-live', 'cells': 1, 'test': 'TestSDKExternalResponseConsumer', 'reason': 'External program must connect to a disposable ordinary-host TLS/gRPC/HTTP relay'},
    {'gate': 'make -j1 check', 'reason': 'Full suite includes listener-dependent relay, auth, HTTP, WebSocket and kernel transports'},
    {'gate': 'deployed client response acceptance', 'reason': 'Requires separate deployed relay/client acceptance'},
]


def matrix_coordinates():
    for scenario in ('cookies', 'status-only', 'flushed', 'trailers'):
        for publisher in ('legacy-map', 'current-list'):
            for relay in ('legacy-map', 'current-list'):
                for mode in ('buffered', 'streaming'):
                    yield scenario, publisher, relay, mode


def matrix_test_names(name):
    return {name + '/' + '/'.join(cell) for cell in matrix_coordinates()
            if cell[0] != 'trailers' or cell[1:3] == ('current-list', 'current-list')}


def inventory(events, test_exit):
    module = 'github.com/ehrlich-b/tunn/'
    runs, outcomes = set(), {}
    bad = []
    packages = {}
    for event in events:
        package, test, action = event.get('Package', ''), event.get('Test'), event.get('Action')
        if test:
            key = (package, test)
            if action == 'run': runs.add(key)
            if action in ('pass', 'fail', 'skip'): outcomes[key] = action
        elif action in ('pass', 'fail'): packages[package] = action
        if action in ('fail', 'skip'): bad.append({'package': package, 'test': test, 'action': action})
    leaves = {key for key in runs if not any(p == key[0] and t.startswith(key[1] + '/') for p, t in runs)}
    result = {'race': 'enabled by make test-http-conformance', 'test_exit': test_exit, 'supported': [], 'explicitly_unsupported': [], 'required_unrun': REQUIRED_UNRUN, 'failures_or_skips': bad}
    ok = test_exit == 0 and not bad
    for package, name, count, *reason in SUPPORTED + UNSUPPORTED:
        selected = {key for key in leaves if key[0] == module + package and (key[1] == name or key[1].startswith(name + '/'))}
        passed = sum(outcomes.get(key) == 'pass' for key in selected)
        verified = len(selected) == count and passed == count and outcomes.get((module + package, name)) == 'pass'
        if name in ('TestHTTPFidelitySDKConformance', 'TestHTTPFidelityRelayConformance'):
            verified &= {test for _, test in selected} == matrix_test_names(name)
        ok &= verified
        cell = {'package': package, 'test': name, 'expected': count, 'executed': len(selected), 'passed': passed, 'gate': 'PASS' if verified else 'FAIL'}
        if reason: cell['policy'] = reason[0]
        result['explicitly_unsupported' if reason else 'supported'].append(cell)
    result['generation_matrix'] = []
    for package, name in (('sdk', 'TestHTTPFidelitySDKConformance'), ('internal/host', 'TestHTTPFidelityRelayConformance')):
        for scenario, publisher, relay, mode in matrix_coordinates():
            cell = {'boundary': package, 'scenario': scenario, 'publisher': publisher, 'relay': relay, 'mode': mode}
            if scenario == 'trailers' and (publisher, relay) != ('current-list', 'current-list'):
                cell['state'] = 'EXPLICITLY-UNSUPPORTED'
                if publisher == 'current-list':
                    proof = ('sdk', f'TestHTTPFidelityTrailers/{mode}/old-relay')
                    cell['policy'] = 'Current publisher explicitly rejects declared trailers at a legacy relay'
                else:
                    proof = ('pkg/proto/tunnelv1', f'TestHTTPFidelityWireVersions/{mode}')
                    cell['policy'] = 'Independent legacy sender schema carries no declared trailer contract'
                cell['evidence'] = '/'.join(proof)
                cell['proof_gate'] = 'PASS' if outcomes.get((module + proof[0], proof[1])) == 'pass' else 'FAIL'
                ok &= cell['proof_gate'] == 'PASS'
            else:
                test = name + '/' + '/'.join((scenario, publisher, relay, mode))
                cell['evidence'] = package + '/' + test
                cell['state'] = 'SUPPORTED' if outcomes.get((module + package, test)) == 'pass' else 'REQUIRED-UNRUN'
                ok &= cell['state'] == 'SUPPORTED'
            result['generation_matrix'].append(cell)
    # Verify explicit legacy trailer rejection separately; no unsupported cell
    # is inferred merely from a test being absent.
    for mode in ('buffered', 'streaming'):
        name = f'TestHTTPFidelityTrailers/{mode}/old-relay'
        verified = outcomes.get((module + 'sdk', name)) == 'pass'
        ok &= verified
        result['explicitly_unsupported'].append({'test': name, 'gate': 'PASS' if verified else 'FAIL', 'policy': 'Declared trailers rejected when current publisher connects to legacy relay'})
    expected_packages = {module + name for name in ('sdk', 'internal/host', 'internal/common', 'internal/client', 'pkg/proto/tunnelv1')}
    if set(packages) != expected_packages or any(value != 'pass' for value in packages.values()): ok = False
    if any(not any(key[0] == package for key in leaves) for package in expected_packages): ok = False
    result['all_leaf_cases'] = len(leaves)
    result['all_passed_leaf_cases'] = sum(outcomes.get(key) == 'pass' for key in leaves)
    result['local_gate'] = 'PASS' if ok else 'FAIL'
    result['ordinary_host_acceptance'] = 'REQUIRED-UNRUN'
    return result, ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--test-exit', type=int, required=True)
    args = parser.parse_args()
    events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
    result, ok = inventory(events, args.test_exit)
    destination = args.events.with_suffix('.inventory.json')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'events': str(args.events), 'inventory': str(destination), 'local_gate': result['local_gate'], 'passed_leaf_cases': result['all_passed_leaf_cases'], 'leaf_cases': result['all_leaf_cases'], 'ordinary_host_acceptance': 'REQUIRED-UNRUN'}))
    return 0 if ok else 1

if __name__ == '__main__': sys.exit(main())
