import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('http-conformance-inventory.py'))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)

class InventoryTest(unittest.TestCase):
    def events(self):
        events = []
        for package, name, count, *_ in inventory.SUPPORTED + inventory.UNSUPPORTED:
            package = 'github.com/ehrlich-b/tunn/' + package
            events.append({'Package': package, 'Test': name, 'Action': 'run'})
            if count > 1:
                if name in ('TestHTTPFidelitySDKConformance', 'TestHTTPFidelityRelayConformance'):
                    names = sorted(inventory.matrix_test_names(name))
                elif name == 'TestHTTPFidelityWireVersions':
                    names = [f'{name}/{mode}' for mode in ('buffered', 'streaming')]
                else:
                    names = [f'{name}/{index}' for index in range(count)]
                for child in names:
                    events.extend([{'Package': package, 'Test': child, 'Action': action} for action in ('run', 'pass')])
            events.append({'Package': package, 'Test': name, 'Action': 'pass'})
        for mode in ('buffered', 'streaming'):
            events.append({'Package': 'github.com/ehrlich-b/tunn/sdk', 'Test': f'TestHTTPFidelityTrailers/{mode}/old-relay', 'Action': 'pass'})
        for name in ('internal/common', 'internal/client'):
            events.extend([{'Package': 'github.com/ehrlich-b/tunn/' + name, 'Test': 'TestHTTPFidelityFixture', 'Action': action} for action in ('run', 'pass')])
        for package in {event['Package'] for event in events}:
            events.append({'Package': package, 'Action': 'pass'})
        return events

    def test_complete_local_evidence_keeps_external_unrun(self):
        result, ok = inventory.inventory(self.events(), 0)
        self.assertTrue(ok)
        self.assertEqual(result['ordinary_host_acceptance'], 'REQUIRED-UNRUN')
        self.assertGreater(len(result['required_unrun']), 0)

    def test_zero_test_success_is_failure(self):
        _, ok = inventory.inventory([{'Package': 'github.com/ehrlich-b/tunn/sdk', 'Action': 'pass'}], 0)
        self.assertFalse(ok)

    def test_missing_case_is_failure(self):
        events = [event for event in self.events() if event.get('Test') != 'TestHTTPFidelitySDKConformance/cookies/legacy-map/legacy-map/buffered']
        _, ok = inventory.inventory(events, 0)
        self.assertFalse(ok)

    def test_substituted_case_with_same_count_is_failure(self):
        events = self.events()
        for event in events:
            if event.get('Test') == 'TestHTTPFidelitySDKConformance/cookies/legacy-map/legacy-map/buffered':
                event['Test'] = 'TestHTTPFidelitySDKConformance/unrelated-case'
        self.assertFalse(inventory.inventory(events, 0)[1])

    def test_skip_or_race_unavailable_is_failure(self):
        events = self.events()
        events.append({'Package': 'github.com/ehrlich-b/tunn/sdk', 'Test': 'TestHTTPFidelityReadDeadline', 'Action': 'skip'})
        self.assertFalse(inventory.inventory(events, 0)[1])
        self.assertFalse(inventory.inventory(self.events(), 2)[1])

if __name__ == '__main__': unittest.main()
