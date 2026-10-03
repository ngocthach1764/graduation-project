import importlib.util
from pathlib import Path
import unittest
import inspect
import pandas as pd

spec = importlib.util.spec_from_file_location('split_training', Path(__file__).with_name('train_service_split.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SplitTests(unittest.TestCase):
    def test_protocol_behavior_is_opt_in_and_recorded(self):
        self.assertFalse(inspect.signature(module.generate).parameters['protocol_behavior'].default)
        source = inspect.getsource(module.generate)
        self.assertIn("command.append('--protocolBehavior=1')", source)
        self.assertIn("meta['command'] != command", source)

    def test_new_seed_groups_are_disjoint(self):
        plan = module.split_plan(600)
        self.assertEqual((plan['train'][0], plan['test'][-1]), (600, 1017))
        groups = [set(values) for values in plan.values()]
        self.assertFalse(groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])

    def test_start_at_run_100(self):
        plan = module.split_plan(100)
        self.assertEqual((plan['train'][0], plan['train'][-1]), (100, 183))
        self.assertEqual((plan['validation'][0], plan['validation'][-1]), (300, 317))
        self.assertEqual((plan['test'][0], plan['test'][-1]), (500, 517))

    def test_modbus_recall_constraint_is_primary(self):
        precise_but_misses = {'OPERATIONAL': {'precision': .95, 'recall': .89, 'f1-score': .92}}
        satisfies = {'OPERATIONAL': {'precision': .70, 'recall': .96, 'f1-score': .81}}
        self.assertGreater(module.rank(satisfies, ['OPERATIONAL'], 'Modbus', .95),
                           module.rank(precise_but_misses, ['OPERATIONAL'], 'Modbus', .95))

    def test_run_group_ratio_and_balance(self):
        plan = module.split_plan()
        self.assertEqual([len(plan[c]) for c in ('train', 'validation', 'test')], [84, 18, 18])
        runs = [run for values in plan.values() for run in values]
        self.assertEqual(len(set(runs)), 120)
        self.assertLess(max(runs), 3000)
        for values in plan.values():
            counts = pd.Series([i % 6 for i in range(len(values))]).value_counts()
            self.assertEqual(counts.nunique(), 1)

    def test_sampling_retains_priority_and_caps_monitoring(self):
        frame = pd.DataFrame([dict(protocol='Modbus', run=2000, service_class='MONITORING')]*500 +
                             [dict(protocol='Modbus', run=2000, service_class='OPERATIONAL')]*20)
        sampled = module.sampled_training(frame)
        self.assertEqual((sampled.service_class == 'OPERATIONAL').sum(), 20)
        self.assertEqual((sampled.service_class == 'MONITORING').sum(), 240)


if __name__ == '__main__':
    unittest.main()
