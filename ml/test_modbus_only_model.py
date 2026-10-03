import importlib.util
from pathlib import Path
import unittest
import numpy as np

spec = importlib.util.spec_from_file_location('modbus_only', Path(__file__).with_name('modbus_only_model.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ModbusOnlyTests(unittest.TestCase):
    def test_only_modbus_rows_replaced_and_tc_absent(self):
        class Fixed:
            def __init__(self, classes, values):
                self.classes_ = np.array(classes)
                self.n_features_in_ = 21
                self.values = values

            def predict_proba(self, x):
                return np.tile(self.values, (len(x), 1))

        frozen = Fixed(['MONITORING', 'OPERATIONAL', 'TIME_CRITICAL'], [.2, .3, .5])
        modbus = Fixed(['MONITORING', 'OPERATIONAL'], [.1, .9])
        wrapper = module.ModbusOnlyModel(frozen, modbus, 20)
        x = np.zeros((4, 21))
        x[:, 20] = [1, 2, 3, 4]
        np.testing.assert_array_equal(wrapper.predict_proba(x)[1:], frozen.predict_proba(x)[1:])
        np.testing.assert_array_equal(wrapper.predict_proba(x)[0], [.1, .9, 0])


if __name__ == '__main__':
    unittest.main()
