import copy
import unittest

from analyze_network import EvidenceError
from native_checkpoint_plan import make_plan, validate_plan


class NativePlanTests(unittest.TestCase):
    def test_every_scenario_changes_first_role(self):
        plan = make_plan()
        validate_plan(plan)
        for sc in plan['scenarios']:
            first = [p['role'] for p in plan['phases'][::2] if p['scenario'] == sc]
            self.assertEqual(len(first), 3)
            self.assertEqual(set(first), {'ref', 'lc'})
        self.assertEqual([p['role'] for p in plan['phases'][::2]
                          if p['scenario'] == 'bigbody'], ['ref', 'lc', 'ref'])

    def test_fixed_role_order_is_rejected(self):
        plan = make_plan()
        for first, second in zip(plan['phases'][::2], plan['phases'][1::2]):
            first['role'], second['role'] = 'ref', 'lc'
        with self.assertRaisesRegex(EvidenceError, 'counterbalance'):
            validate_plan(plan)

    def test_changed_coverage_pairing_or_criteria_is_rejected(self):
        baseline = make_plan()
        changes = []
        p = copy.deepcopy(baseline); p['phases'].pop(); changes.append(p)
        p = copy.deepcopy(baseline); p['phases'][0]['sample'] = 2; changes.append(p)
        p = copy.deepcopy(baseline); p['phases'][0]['id'] = 9; changes.append(p)
        p = copy.deepcopy(baseline); p['criteria']['timing_regression_us'] = 101; changes.append(p)
        p = copy.deepcopy(baseline); p['schema'] = 'native-g2-checkpoint-v1'; changes.append(p)
        p = copy.deepcopy(baseline); p['schema'] = 'native-g2-checkpoint-v2'; changes.append(p)
        p = copy.deepcopy(baseline); p['schema'] = 'native-g2-checkpoint-v3'; changes.append(p)
        p = copy.deepcopy(baseline); p['criteria'] = dict(rate_gap_pp=10, timing_median_us=100); changes.append(p)
        p = copy.deepcopy(baseline); p.pop('criteria_frozen'); p['criteria_changed'] = False; changes.append(p)
        p = copy.deepcopy(baseline); p['guard_memavailable_kib'] = 1024; changes.append(p)
        p = copy.deepcopy(baseline); p['resource_policy'] = 'ram-and-flash'; changes.append(p)
        p = copy.deepcopy(baseline); p['G2Closed'] = False; changes.append(p)
        p = copy.deepcopy(baseline); p['acceptance_scope'] = 'release'; changes.append(p)
        p = copy.deepcopy(baseline); p['criteria']['rate_gap_pp'] = 10; changes.append(p)
        p = copy.deepcopy(baseline); p['phases'][0], p['phases'][2] = p['phases'][2], p['phases'][0]
        for i, phase in enumerate(p['phases']): phase['id'] = i
        changes.append(p)
        for plan in changes:
            with self.subTest(plan=plan), self.assertRaises(EvidenceError):
                validate_plan(plan)


if __name__ == '__main__':
    unittest.main()
