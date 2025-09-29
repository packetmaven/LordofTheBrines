import logging
import os
import pickle as pkl
from typing import Dict, List, Tuple, Any
import math
from ml_detector import SimpleMLDetector
from bayesian import NaiveBayesPickle

from config import Config

logger = logging.getLogger(__name__)


class ModelEnsemble:
    """
    Ensemble of detection models for malicious pickle detection.
    
    This class combines multiple detection models to achieve optimal detection performance with uncertainty quantification.
    """
    def __init__(self, config: Config):
        self.config = config
        self.models = {}
        self.ml_detector = SimpleMLDetector()
        self.bayes_detector = NaiveBayesPickle()
        logger.info("Initializing model ensemble")
        self._load_models()

    def _load_models(self):
        if self.config.custom_model_path and os.path.exists(self.config.custom_model_path):
            try:
                with open(self.config.custom_model_path, "rb") as f:
                    custom_model = pkl.load(f)
                self.models["custom"] = custom_model
                logger.info(f"Loaded custom model from {self.config.custom_model_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load custom model: {e}")
        
        model_weights = self.config.model_ensemble_weights
        
        for model_name, weight in model_weights.items():
            if weight > 0:
                self.models[model_name] = self._create_mock_model(model_name)
                logger.info(f"Loaded model: {model_name} (weight: {weight})")
        
        if not self.models:
            logger.warning("No models loaded, using default model")
            self.models["default"] = self._create_mock_model("default")

    def _create_mock_model(self, model_name: str) -> Dict[str, Any]:
        return {
            "name": model_name,
            "version": "0.1.0",
            "type": model_name,
            "feature_importance": self._get_mock_feature_importance(model_name),
        }

    def _get_mock_feature_importance(self, model_name: str) -> Dict[str, float]:
        if model_name == "gradient_boosting":
            return {
                "suspicious_opcode_ratio": 0.25,
                "entropy": 0.15,
                "has_modules": 0.12,
                "has_functions": 0.10,
                "max_depth": 0.08,
                "compression_ratio": 0.07,
                "printable_ratio": 0.06,
                "opcode_count": 0.05,
                "byte_diversity": 0.04,
                "object_count": 0.03,
                "null_byte_ratio": 0.03,
                "high_bit_ratio": 0.02,
            }
        elif model_name == "random_forest":
            return {
                "suspicious_opcode_ratio": 0.22,
                "has_modules": 0.15,
                "entropy": 0.13,
                "has_functions": 0.11,
                "max_depth": 0.09,
                "compression_ratio": 0.08,
                "printable_ratio": 0.07,
                "opcode_count": 0.06,
                "byte_diversity": 0.04,
                "object_count": 0.03,
                "null_byte_ratio": 0.01,
                "high_bit_ratio": 0.01,
            }
        elif model_name == "neural_network":
            return {
                "suspicious_opcode_ratio": 0.20,
                "entropy": 0.18,
                "has_modules": 0.14,
                "has_functions": 0.12,
                "max_depth": 0.10,
                "compression_ratio": 0.08,
                "printable_ratio": 0.06,
                "opcode_count": 0.05,
                "byte_diversity": 0.03,
                "object_count": 0.02,
                "null_byte_ratio": 0.01,
                "high_bit_ratio": 0.01,
            }
        else:
            return {
                "suspicious_opcode_ratio": 0.30,
                "entropy": 0.20,
                "has_modules": 0.15,
                "has_functions": 0.10,
                "max_depth": 0.10,
                "compression_ratio": 0.05,
                "printable_ratio": 0.05,
                "opcode_count": 0.05,
            }

    def predict(self, features: Dict[str, Any]) -> Tuple[bool, float, Dict[str, float]]:
        if not self.models:
            raise ValueError("No models available for prediction")
        
        logger.info("Making prediction with model ensemble")
        
        predictions = []
        confidences = []
        
        for model_name, model in self.models.items():
            weight = self.config.model_ensemble_weights.get(model_name, 1.0)
            
            prediction, confidence = self._mock_predict(model, features)
            
            predictions.append((prediction, weight))
            confidences.append((confidence, weight))
            
            logger.debug(f"Model {model_name}: prediction={prediction}, confidence={confidence}")
        
        # Optional ML anomaly score as an additional weighted vote (maps to boolean via threshold)
        ml_weight = 0.0
        ml_vote = 0.0
        try:
            ml_enabled = getattr(self.config, 'enable_ml_detector', True)
        except Exception:
            ml_enabled = True
        if ml_enabled:
            ml_score = self.ml_detector.predict_score(features)
            ml_vote = 1.0 if ml_score >= 0.65 else 0.0
            ml_weight = self.config.model_ensemble_weights.get('ml_detector', 0.5)

        # Optional Bayesian probability blended as a vote
        bayes_weight = 0.0
        bayes_vote = 0.0
        try:
            bayes_enabled = getattr(self.config, 'enable_bayesian_detector', True)
        except Exception:
            bayes_enabled = True
        if bayes_enabled:
            bayes_prob = float(self.bayes_detector.predict_proba(features))
            bayes_vote = 1.0 if bayes_prob >= 0.6 else 0.0
            bayes_weight = self.config.model_ensemble_weights.get('bayesian_detector', 0.4)

        total_weight = sum(weight for _, weight in predictions) + ml_weight + bayes_weight
        numerator = sum(pred * weight for pred, weight in predictions) + ml_vote * ml_weight + bayes_vote * bayes_weight
        weighted_sum = (numerator / total_weight) if total_weight > 0 else 0.0
        is_malicious = bool(weighted_sum >= 0.5)
        raw_confidence = self._calculate_ensemble_confidence(confidences)
        calibrated_confidence = self._apply_temperature_scaling(raw_confidence, features)
        
        feature_importances = self._combine_feature_importances()
        
        logger.info(f"Ensemble prediction: is_malicious={is_malicious}, confidence={calibrated_confidence:.4f}")
        
        return is_malicious, calibrated_confidence, feature_importances

    def _mock_predict(self, model: Dict[str, Any], features: Dict[str, Any]) -> Tuple[bool, float]:
        score = 0.0

        has_global_opcode = features.get("opcode_GLOBAL", 0) > 0
        has_reduce_opcode = features.get("opcode_REDUCE", 0) > 0
        stack_global_count = features.get("opcode_STACK_GLOBAL", 0)
        tuple1 = features.get("opcode_TUPLE1", 0)
        tuple2 = features.get("opcode_TUPLE2", 0)
        tuple3 = features.get("opcode_TUPLE3", 0)
        has_suspicious_modules = features.get("has_suspicious_modules", False)
        has_suspicious_functions = features.get("has_suspicious_functions", False)
        has_indirection_strings = bool(features.get("has_indirection_strings", False))
        has_eval_string = bool(features.get("has_eval_string", False))
        has_dynamic_import_string = bool(features.get("has_dynamic_import_string", False))
        has_getattr_import_string = bool(features.get("has_getattr_import_string", False))
        has_builtins_indicators = bool(features.get("has_builtins_indicators", False))
        has_base64_any = bool(features.get("has_base64_suspicious_any", False))
        has_base64_multiple = bool(features.get("has_base64_multiple_tokens", False))
        has_norm_any = bool(features.get("has_normalized_suspicious_any", False))
        has_norm_multiple = bool(features.get("has_normalized_multiple_tokens", False))
        has_pip_main = bool(features.get("has_pip_main_call", False))
        has_pip_install = bool(features.get("has_pip_install_string", False))
        has_marshal = bool(features.get("has_marshal_usage", False))
        is_joblib = bool(features.get("is_joblib_artifact", False))
        zip_bad_names = bool(features.get("zip_suspicious_names", False))
        zip_bad_flags = bool(features.get("zip_suspicious_flags", False))
        has_pickle_name_only = bool(features.get("has_pickle_name_only", False))
        suspicious_opcode_ratio = features.get("suspicious_opcode_ratio", 0)
        entropy = features.get("entropy", 0)
        opcode_count = features.get("opcode_count", 0)
        object_count = features.get("object_count", 0)
        max_depth = features.get("max_depth", 0)

        # Rule 1: Very strong indicator - GLOBAL/REDUCE with suspicious modules/functions
        if (has_global_opcode or has_reduce_opcode) and (has_suspicious_modules or has_suspicious_functions):
            score = 0.99 # Very high score for direct code execution via known modules/functions
        
        # Rule 2: Strong indicator - High suspicious opcode ratio and presence of suspicious modules/functions
        elif suspicious_opcode_ratio > 0.5 and (has_suspicious_modules or has_suspicious_functions):
            score = 0.90 # High score for general suspiciousness combined with specific indicators
        
        # Rule 3: Moderate indicator - Low entropy combined with some suspicious opcodes or high object/depth count
        elif entropy < 4.0 and (has_global_opcode or has_reduce_opcode or suspicious_opcode_ratio > 0.2 or object_count > 10 or max_depth > 5):
            score = 0.75 # Moderate score if low entropy is combined with other suspicious signs or complex structure

        # Rule 4: Presence of specific suspicious opcodes without other strong indicators
        elif features.get("opcode_NEWOBJ", 0) > 0 or features.get("opcode_INST", 0) > 0 or features.get("opcode_BUILD", 0) > 0:
            score = 0.60 # Suspicious opcodes often used in exploits

        # Rule 4b: Indirection strings via eval/__import__/getattr
        # If we see these strings along with GLOBAL/REDUCE/STACK_GLOBAL or non-trivial suspicious opcode ratio, bias high
        if has_indirection_strings and (has_global_opcode or has_reduce_opcode or stack_global_count > 0 or suspicious_opcode_ratio >= 0.05):
            # Stronger if clearly eval + __import__ or getattr(__import__)
            if (has_eval_string and (has_dynamic_import_string or has_getattr_import_string)) or has_getattr_import_string:
                score = max(score, 0.90)
            else:
                score = max(score, 0.75)

        # Rule 4c: Classic pattern STACK_GLOBAL + TUPLE{1,2,3} + REDUCE
        if stack_global_count > 0 and (tuple1 > 0 or tuple2 > 0 or tuple3 > 0) and has_reduce_opcode:
            score = max(score, 0.70)

        # Rule 4d: builtins + base64 indicators
        # If builtins.* present and base64 suspicious tokens present, elevate risk even without explicit modules/functions
        if has_builtins_indicators and (has_base64_any or has_indirection_strings):
            score = max(score, 0.70)
            if has_base64_multiple:
                score = max(score, 0.80)
        # Normalized token hits can indicate obfuscated strings
        if has_norm_any:
            score = max(score, 0.65)
        if has_norm_multiple:
            score = max(score, 0.75)
        # pip install attempts -> high risk
        if has_pip_main or has_pip_install:
            score = max(score, 0.90)
        # marshal usage in pickle context is suspicious
        if has_marshal:
            score = max(score, 0.80)
        # suspicious ZIP metadata: weak nudge only
        if zip_bad_names or zip_bad_flags:
            score = max(score, 0.45)
        # joblib artifacts often containerize numpy/mmap arrays; do not auto-flag, but if other signals present, bias
        if is_joblib and (has_suspicious_modules or has_suspicious_functions or has_norm_any or has_base64_any):
            score = max(score, 0.70)

        # Rule 5: Harmless pickle detection - very low score if clearly benign
        # This rule is placed after malicious rules to prioritize detection of threats.
        if not has_global_opcode and not has_reduce_opcode and not has_suspicious_modules and not has_suspicious_functions and not has_indirection_strings and suspicious_opcode_ratio < 0.05 and entropy > 6.0 and opcode_count < 20 and object_count < 5:
            score = 0.01 # Very low score for clearly harmless pickles
        
        # Rule 6: Potentially harmless but with some minor suspiciousness - low score
        elif not has_global_opcode and not has_reduce_opcode and not has_suspicious_modules and not has_suspicious_functions and not has_indirection_strings and suspicious_opcode_ratio < 0.1:
            score = 0.15 # Slightly higher score for less clear harmless cases, still below malicious threshold

        # Torch strict mode heuristic: Torch artifact, trivial opcode count but suspicious strings
        if getattr(self.config, 'strict_torch', False):
            is_torch = bool(features.get('is_torch_artifact'))
            trivial_ops = features.get('opcode_count', 0) <= 3
            has_torch_strings = bool(features.get('has_suspicious_torch_strings'))
            if is_torch and (trivial_ops or suspicious_opcode_ratio < 0.02) and (has_torch_strings or has_suspicious_modules or has_suspicious_functions):
                score = max(score, 0.55)

        # Containerized pickle heuristic: only strong if actual inner pickle parsed
        if features.get("has_inner_pickle"):
            score = max(score, 0.60)
        # If only names suggest pickle without decode, very weak nudge
        if has_pickle_name_only or features.get("has_nested_zip"):
            score = max(score, 0.48)

        # Ensure score is within bounds [0, 1]
        score = max(0.0, min(1.0, score))

        # Determine maliciousness based on a higher threshold
        is_malicious = score >= 0.5 # Adjusted threshold for malicious classification

        # Attach simple explanation for top reasons
        # Note: Explanation is produced in detector.scan_data to avoid duplication here.

        # Determine confidence: higher score means higher confidence in maliciousness
        if is_malicious:
            confidence = 0.5 + (score / 2) # Scale score to 0.5-1.0 for malicious
        else:
            confidence = 0.5 + ((1 - score) / 2) # Scale inverse score to 0.5-1.0 for benign

        # Return explanation via a side channel in predict() caller; here we just return pair
        # The predict() caller already builds feature_importances and packs explanation in DetectionResult.
        # We piggyback by attaching to model dict for the caller to read; simpler: return tuple of 2; caller ignores explanation.
        return is_malicious, confidence

    def _calculate_ensemble_confidence(self, confidences: List[Tuple[float, float]]) -> float:
        total_weight = sum(weight for _, weight in confidences)
        weighted_confidence = sum(conf * weight for conf, weight in confidences) / total_weight
        
        return weighted_confidence

    def _apply_temperature_scaling(self, confidence: float, features: Dict[str, Any]) -> float:
        if not getattr(self.config, 'enable_confidence_calibration', True):
            return confidence

        strategy = getattr(self.config, 'calibration_strategy', 'rule_based')
        T = float(getattr(self.config, 'calibration_temperature', 1.15))

        # Rule-based dynamic temperature: stronger evidence -> lower T (sharper), weak/ambiguous -> higher T (softer)
        if strategy == 'rule_based':
            strong = 0
            if features.get("opcode_REDUCE", 0) > 0 and (features.get("opcode_GLOBAL", 0) > 0 or features.get("opcode_STACK_GLOBAL", 0) > 0):
                strong += 1
            if features.get("has_indirection_strings") or features.get("has_builtins_indicators"):
                strong += 1
            if features.get("has_pip_install_string") or features.get("has_pip_main_call"):
                strong += 1
            if features.get("has_marshal_usage"):
                strong += 1
            if features.get("has_normalized_multiple_tokens") or features.get("has_base64_multiple_tokens"):
                strong += 1
            if features.get("has_inner_pickle"):
                strong += 1

            if strong >= 3:
                T = 0.85
            elif strong == 2:
                T = 1.0
            elif strong <= 1:
                T = max(T, 1.25)

        # Stable logistic calibration
        p = max(0.0001, min(0.9999, confidence))
        logit = math.log(p / (1 - p))
        scaled = logit / max(0.05, T)
        return 1.0 / (1.0 + math.exp(-scaled))

    def get_top_explanations(self, features: Dict[str, Any]) -> List[str]:
        reasons: List[Tuple[str, float]] = []
        # Weight reasons by indicative severity based on current research for pickle RCE
        if (features.get("opcode_REDUCE", 0) > 0) and (features.get("opcode_GLOBAL", 0) > 0 or features.get("opcode_STACK_GLOBAL", 0) > 0):
            reasons.append(("Opcode chain: GLOBAL/STACK_GLOBAL + REDUCE", 1.0))
        if features.get("has_indirection_strings"):
            reasons.append(("Import indirection/eval strings present", 0.9))
        if features.get("has_builtins_indicators"):
            reasons.append(("builtins.* abuse indicators present", 0.85))
        if features.get("has_pip_install_string") or features.get("has_pip_main_call"):
            reasons.append(("pip install/main invocation in payload", 0.95))
        if features.get("has_marshal_usage"):
            reasons.append(("marshal.loads usage in payload", 0.9))
        if features.get("has_base64_multiple_tokens") or features.get("has_base64_suspicious_any"):
            reasons.append(("base64-encoded suspicious tokens", 0.7))
        if features.get("has_normalized_multiple_tokens") or features.get("has_normalized_suspicious_any"):
            reasons.append(("normalized (homoglyph/ZW) suspicious tokens", 0.7))
        if features.get("has_inner_pickle"):
            reasons.append(("Embedded inner pickle present (container/prefixed)", 0.6))
        if features.get("zip_suspicious_names") or features.get("zip_suspicious_flags"):
            reasons.append(("suspicious archive names/flags", 0.5))
        if features.get("strict_torch") and features.get("is_torch_artifact") and (features.get("opcode_count", 0) <= 3):
            reasons.append(("strict torch heuristic: trivial opcodes + torch strings", 0.55))
        # General opcode suspicion
        sus_ratio = float(features.get("suspicious_opcode_ratio", 0.0))
        if sus_ratio >= 0.2:
            reasons.append((f"elevated suspicious opcode ratio ({sus_ratio:.2f})", 0.65))
        # YARA/Fickling integrations
        try:
            yhits = int(features.get("yara_hits", 0))
            if yhits > 0:
                matched = features.get("yara_matched_rules", [])
                if matched:
                    reasons.append((f"YARA rule match: {matched[0]}", 0.9))
                else:
                    reasons.append(("YARA matches present", 0.8))
        except Exception:
            pass
        try:
            fhits = int(features.get("fickling_hits", 0))
            if fhits > 0:
                reasons.append(("Fickling unsafe ops detected", 0.85))
        except Exception:
            pass

        reasons.sort(key=lambda x: x[1], reverse=True)
        k = int(getattr(self.config, 'max_explanations', 3))
        return [r for r, _ in reasons[:max(1, k)]]

    def _combine_feature_importances(self) -> Dict[str, float]:
        combined_importances = {}
        
        for model_name, model in self.models.items():
            weight = self.config.model_ensemble_weights.get(model_name, 1.0)
            
            if "feature_importance" in model:
                for feature, importance in model["feature_importance"].items():
                    if feature not in combined_importances:
                        combined_importances[feature] = 0.0
                    
                    combined_importances[feature] += importance * weight
        
        total = sum(combined_importances.values())
        if total > 0:
            for feature in combined_importances:
                combined_importances[feature] /= total
        
        return combined_importances


