import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


FEATURE_KEYS: List[str] = [
    "opcode_count",
    "suspicious_opcode_ratio",
    "entropy",
    "object_count",
    "max_depth",
    "printable_ratio",
    "null_byte_ratio",
    "high_bit_ratio",
    "compression_ratio",
    "byte_diversity",
]


def _extract_vector(features: Dict[str, float]) -> List[float]:
    vec: List[float] = []
    for k in FEATURE_KEYS:
        v = features.get(k, 0.0)
        try:
            vec.append(float(v))
        except Exception:
            vec.append(0.0)
    # Append select boolean indicators as ints
    for bkey in (
        "has_suspicious_modules",
        "has_suspicious_functions",
        "has_indirection_strings",
        "has_builtins_indicators",
        "has_base64_suspicious_any",
        "has_normalized_suspicious_any",
        "has_inner_pickle",
    ):
        vec.append(1.0 if bool(features.get(bkey)) else 0.0)
    return vec


class SimpleMLDetector:
    """
    Optional ML-based anomaly detector.
    - Uses scikit-learn IsolationForest/OneClassSVM if available
    - Falls back to a simple heuristic if sklearn is not installed
    """

    def __init__(self) -> None:
        self._sklearn_ok = False
        self._iforest = None
        self._ocsvm = None
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
            from sklearn.svm import OneClassSVM  # type: ignore
            self._sklearn_ok = True
            # Lazy-fit on first prediction with synthetic baseline
        except Exception:
            self._sklearn_ok = False

    def _lazy_fit(self, dim: int) -> None:
        if not self._sklearn_ok:
            return
        if self._iforest is not None and self._ocsvm is not None:
            return
        try:
            import numpy as np  # type: ignore
            from sklearn.ensemble import IsolationForest  # type: ignore
            from sklearn.svm import OneClassSVM  # type: ignore
            baseline = np.random.randn(2000, dim) * 0.3
            self._iforest = IsolationForest(contamination=0.1, random_state=13)
            self._iforest.fit(baseline)
            self._ocsvm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
            self._ocsvm.fit(baseline)
        except Exception as e:
            logger.warning(f"MLDetector lazy fit failed: {e}")
            self._sklearn_ok = False

    def predict_score(self, features: Dict[str, float]) -> float:
        vec_list = _extract_vector(features)
        dim = len(vec_list)
        if dim == 0:
            return 0.5
        if self._sklearn_ok:
            try:
                import numpy as np  # type: ignore
                self._lazy_fit(dim)
                x = np.array(vec_list, dtype=float).reshape(1, -1)
                if_score = 0.0
                oc_score = 0.0
                try:
                    if_score = -float(self._iforest.score_samples(x)[0])  # higher = more anomalous
                except Exception:
                    pass
                try:
                    # decision_function > 0 is inlier; convert to anomaly prob-ish
                    oc_dec = float(self._ocsvm.decision_function(x)[0])
                    oc_score = max(0.0, 1.0 - (oc_dec + 1.0) / 2.0)
                except Exception:
                    pass
                # Blend and squash to [0,1]
                score = max(0.0, min(1.0, 0.6 * (if_score / 5.0) + 0.4 * oc_score))
                return score
            except Exception as e:
                logger.debug(f"MLDetector sklearn predict failed, using heuristic: {e}")

        # Heuristic fallback: high entropy + non-trivial suspicious ratio
        entropy = float(features.get("entropy", 0.0))
        sus_ratio = float(features.get("suspicious_opcode_ratio", 0.0))
        inner = bool(features.get("has_inner_pickle", False))
        pipi = bool(features.get("has_pip_install_string", False)) or bool(features.get("has_pip_main_call", False))
        base = 0.5
        if entropy >= 6.5:
            base = max(base, 0.7)
        if sus_ratio >= 0.2:
            base = max(base, 0.8)
        if inner or pipi:
            base = max(base, 0.85)
        return base


