"""
Core detector module for LordofTheBrines.
"""
import logging
import os
from typing import Dict, Any

from config import Config
from result import DetectionResult
import extractor
import ensemble
from yara_detector import scan_bytes as yara_scan
from fickling_hook import validate_bytes as fickling_validate

logger = logging.getLogger("lordofthebrines.detector")


class LordofTheBrines:
    """
    Main class for the LordofTheBrines detection system.
    """

    def __init__(self, config: Config):
        self.config = config
        logger.info("Initializing LordofTheBrines detector")
        self.feature_extractor = extractor.FeatureExtractor(config)
        self.model_ensemble = ensemble.ModelEnsemble(config)
        logger.info("LordofTheBrines detector initialized successfully")

    def scan_file(self, file_path: str) -> DetectionResult:
        logger.info(f"Scanning file: {file_path}")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            pickle_data = f.read()
        
        return self.scan_data(pickle_data, file_path)

    def scan_data(self, data: bytes, file_name: str = "<in_memory_pickle>") -> DetectionResult:
        logger.info(f"Scanning pickle data ({len(data)} bytes)")
        try:
            # 1. Feature Extraction
            features = self.feature_extractor.extract_features(data)
            logger.debug(f"Extracted features: {features}")

            # 1b. Optional YARA/Fickling enrichment
            try:
                if getattr(self.config, 'enable_yara', False):
                    rules_path = getattr(self.config, 'yara_rules_path', None)
                    yres = yara_scan(data, rules_path)
                    features.update(yres)
                if getattr(self.config, 'enable_fickling_hook', False):
                    fres = fickling_validate(data)
                    features.update(fres)
            except Exception as enr_e:
                logger.debug(f"Enrichment failed: {enr_e}")

            # 2. Model Prediction
            is_malicious, confidence, feature_importances = self.model_ensemble.predict(features)

            # 3. Result Formulation
            threat_type = "Malicious" if is_malicious else "Benign"
            if is_malicious:
                reasons = self.model_ensemble.get_top_explanations(features)
                explanation = "; ".join(reasons) if reasons else "Malicious pickle detected."
            else:
                explanation = "Benign pickle detected."

            result = DetectionResult(
                file=file_name,
                is_malicious=is_malicious,
                confidence=confidence,
                threat_type=threat_type,
                explanation=explanation,
                feature_importances=feature_importances,
                features=features # Pass the extracted features to the result
            )
            return result

        except Exception as e:
            logger.error(f"Error scanning pickle data: {e}")
            return DetectionResult(
                file=file_name,
                is_malicious=False,  # Default to benign on error
                confidence=0.0,
                threat_type="Error",
                explanation=f"An error occurred during scanning: {e}",
                feature_importances={},
                features={}
            )


