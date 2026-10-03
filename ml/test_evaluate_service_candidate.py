import importlib.util
from pathlib import Path
import unittest
import numpy as np

spec = importlib.util.spec_from_file_location('candidate_eval', Path(__file__).with_name('evaluate_service_candidate.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MetricTests(unittest.TestCase):
    def test_csv_rounding_requires_matching_probability_vector(self):
        class BoundaryModel:
            classes_ = np.array(['MONITORING', 'OPERATIONAL', 'TIME_CRITICAL'])

            def predict_proba(self, x):
                return np.array([[.75, .23, .02] if row[0] < 1.1547008
                                 else [.76, .22, .02] for row in x])

        model = BoundaryModel()
        match = module.explain_csv_rounding(model, np.array([1.154701]),
            dict(MONITORING=.75, OPERATIONAL=.23, TIME_CRITICAL=.02), ['std'])
        self.assertTrue(match)
        invalid = module.explain_csv_rounding(model, np.array([1.154701]),
            dict(MONITORING=.50, OPERATIONAL=.48, TIME_CRITICAL=.02), ['std'])
        self.assertFalse(invalid)

    def test_confusion_orientation(self):
        actual = ['TIME_CRITICAL', 'TIME_CRITICAL', 'OPERATIONAL', 'MONITORING']
        predicted = ['TIME_CRITICAL', 'OPERATIONAL', 'OPERATIONAL', 'MONITORING']
        np.testing.assert_array_equal(module.matrix(actual, predicted), [[1, 1, 0], [0, 1, 0], [0, 0, 1]])

    def test_missing_modbus_tc_is_not_perfect(self):
        rows, summary = module.measures(np.array([[0, 0, 0], [0, 9, 1], [0, 2, 88]]))
        self.assertIsNone(rows[0]['recall_pct'])
        self.assertIsNone(rows[0]['f1_pct'])
        self.assertEqual(summary['active_classes'], 2)
        self.assertEqual(summary['support'], 100)
        self.assertEqual(summary['accuracy_pct'], 97)
        self.assertAlmostEqual(rows[1]['precision_pct'], 900/11)
        self.assertEqual(rows[1]['recall_pct'], 90)


if __name__ == '__main__':
    unittest.main()
