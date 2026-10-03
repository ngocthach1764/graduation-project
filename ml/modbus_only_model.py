"""Frozen non-Modbus classifier with a separately trained Modbus branch."""
import numpy as np


class ModbusOnlyModel:
    def __init__(self, frozen, modbus, protocol_index):
        self.frozen = frozen
        self.modbus = modbus
        self.protocol_index = protocol_index
        self.classes_ = frozen.classes_
        self.n_features_in_ = frozen.n_features_in_

    def predict_proba(self, x):
        x = np.asarray(x, dtype=float)
        result = self.frozen.predict_proba(x)
        mask = x[:, self.protocol_index] == 1
        if mask.any():
            result[mask] = 0.0
            values = self.modbus.predict_proba(x[mask])
            for index, name in enumerate(self.modbus.classes_):
                result[mask, list(self.classes_).index(name)] = values[:, index]
        return result
