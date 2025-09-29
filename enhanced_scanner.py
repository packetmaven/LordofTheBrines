import logging
from typing import Dict, Any, Optional
import json
import os
try:
    from skmultiflow.drift_detection.adwin import ADWIN  # type: ignore
except Exception:
    ADWIN = None  # optional

from config import Config
from detector import LordofTheBrines

logger = logging.getLogger(__name__)


class EnhancedPickleScanner:
    """
    Orchestrator that wraps detector and exposes a simple API for full-stack scans.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.detector = LordofTheBrines(self.config)
        # Optional ADWIN drift detector per key
        self._adwin_detectors: Dict[str, Any] = {}
        self._adwin_state_path = os.path.join(os.path.dirname(__file__), ".drift_state.json")
        self._load_adwin_state()

    def scan_file(self, path: str) -> Dict[str, Any]:
        res = self.detector.scan_file(path)
        self._drift_check(res.features)
        return res.to_dict()

    def scan_bytes(self, data: bytes, name: str = "<bytes>") -> Dict[str, Any]:
        res = self.detector.scan_data(data, name)
        self._drift_check(res.features)
        return res.to_dict()

    def _drift_check(self, features: Dict[str, Any]) -> None:
        try:
            if not getattr(self.config, 'enable_drift_monitor', False):
                return
            # Prefer ADWIN if available and enabled; otherwise fallback to z-score
            if getattr(self.config, 'enable_adwin_drift', True) and ADWIN is not None:
                # Monitor a small set of numeric features
                for key in ("suspicious_opcode_ratio", "entropy", "opcode_count"):
                    try:
                        val = float(features.get(key, 0.0))
                        adw = self._adwin_detectors.get(key)
                        if adw is None:
                            delta = float(getattr(self.config, 'adwin_delta', 0.002))
                            adw = ADWIN(delta=delta)
                            self._adwin_detectors[key] = adw
                        adw.add_element(val)
                        if adw.detected_change():
                            logger.warning(f"ADWIN drift detected for {key}: value={val:.4f}")
                            # Safe auto-threshold adjust: slightly lower threshold when drift is increasing suspiciousness
                            try:
                                if key == "suspicious_opcode_ratio" and val > 0.1:
                                    thr = float(getattr(self.config, 'detection_threshold', 0.8))
                                    new_thr = max(0.5, thr - 0.05)
                                    self.config.detection_threshold = new_thr
                                    logger.info(f"Auto-adjust detection_threshold to {new_thr:.2f} due to drift")
                            except Exception:
                                pass
                    except Exception:
                        continue
                self._save_adwin_state()
            else:
                baseline = getattr(self.config, 'drift_baseline', {})
                for key, params in baseline.items():
                    x = float(features.get(key, 0.0))
                    mu = float(params.get('mean', 0.0))
                    sigma = float(params.get('std', 1.0)) or 1.0
                    z = abs((x - mu) / sigma)
                    if z > 3.5:
                        logger.info(f"Drift alert: feature {key} value {x:.3f} z={z:.2f} (baseline mu={mu}, sigma={sigma})")
        except Exception:
            pass

    def _load_adwin_state(self) -> None:
        try:
            if not os.path.exists(self._adwin_state_path):
                return
            with open(self._adwin_state_path, 'r') as fh:
                state = json.load(fh)
            # We only persist minimal metadata; ADWIN objects are not trivially serializable
            # so we re-initialize with stored deltas and window sizes if present
            # For simplicity, we just restore config-level params
            pass
        except Exception:
            pass

    def _save_adwin_state(self) -> None:
        try:
            state = {"adwin_keys": list(self._adwin_detectors.keys()), "delta": float(getattr(self.config, 'adwin_delta', 0.002))}
            with open(self._adwin_state_path, 'w') as fh:
                json.dump(state, fh)
        except Exception:
            pass


