"""
Unit tests for the core functionality of LordofTheBrines for the core function.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from config import Config
from detector import LordofTheBrines
from result import DetectionResult

import io
import zipfile
import tarfile
import gzip
import pickle as pkl


class TestConfig(unittest.TestCase):
    """Test cases for the Config class."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        self.assertEqual(config.detection_threshold, 0.8)
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.feature_selection_method, "hybrid")
        self.assertFalse(config.enable_behavioral_analysis)
        self.assertFalse(config.enable_threat_intelligence)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = Config()
        config_dict = config.to_dict()
        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict["detection_threshold"], 0.8)
        self.assertEqual(config_dict["log_level"], "INFO")

    def test_from_dict(self):
        """Test creation from dictionary."""
        config_dict = {
            "detection_threshold": 0.9,
            "log_level": "DEBUG",
            "feature_selection_method": "none",
            "enable_behavioral_analysis": True,
        }
        config = Config.from_dict(config_dict)
        self.assertEqual(config.detection_threshold, 0.9)
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.feature_selection_method, "none")
        self.assertTrue(config.enable_behavioral_analysis)

    def test_save_and_load(self):
        """Test saving and loading from file."""
        config = Config()
        config.detection_threshold = 0.95
        config.log_level = "DEBUG"
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Save to file
            config.save_to_file(temp_path)
            
            # Load from file
            loaded_config = Config.from_file(temp_path)
            
            # Check values
            self.assertEqual(loaded_config.detection_threshold, 0.95)
            self.assertEqual(loaded_config.log_level, "DEBUG")
        finally:
            # Clean up
            os.unlink(temp_path)


class TestDetectionResult(unittest.TestCase):
    """Test cases for the DetectionResult class."""

    def test_init(self):
        """Test initialization."""
        result = DetectionResult(is_malicious=True, confidence=0.9)
        self.assertTrue(result.is_malicious)
        self.assertEqual(result.confidence, 0.9)
        self.assertEqual(result.threat_type, "Unknown")  # Default value

    def test_validation(self):
        """Test validation of confidence values."""
        with self.assertRaises(ValueError):
            DetectionResult(is_malicious=True, confidence=1.5)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = DetectionResult(
            is_malicious=True,
            confidence=0.9,
            threat_type="Test Threat",
            explanation="Test explanation"
        )
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertTrue(result_dict["is_malicious"])
        self.assertEqual(result_dict["confidence"], 0.9)
        self.assertEqual(result_dict["threat_type"], "Test Threat")
        self.assertEqual(result_dict["explanation"], "Test explanation")

    def test_from_dict(self):
        """Test creation from dictionary."""
        result_dict = {
            "is_malicious": True,
            "confidence": 0.9,
            "threat_type": "Test Threat",
            "explanation": "Test explanation"
        }
        result = DetectionResult.from_dict(result_dict)
        self.assertTrue(result.is_malicious)
        self.assertEqual(result.confidence, 0.9)
        self.assertEqual(result.threat_type, "Test Threat")
        self.assertEqual(result.explanation, "Test explanation")

    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        result = DetectionResult(
            is_malicious=True,
            confidence=0.9,
            threat_type="Test Threat",
            explanation="Test explanation"
        )
        json_str = result.to_json()
        loaded_result = DetectionResult.from_json(json_str)
        self.assertTrue(loaded_result.is_malicious)
        self.assertEqual(loaded_result.confidence, 0.9)
        self.assertEqual(loaded_result.threat_type, "Test Threat")
        self.assertEqual(loaded_result.explanation, "Test explanation")


class TestLordofTheBrines(unittest.TestCase):
    """Test cases for the LordofTheBrines class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = Config()
        self.test_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_file.write(b"test pickle data")
        self.test_file.seek(0)

        self.sample_features = {"feature1": 0.5, "feature2": 0.3}
        self.sample_importances = {"feature1": 0.8, "feature2": 0.2}

    def tearDown(self):
        """Tear down test fixtures."""
        # NamedTemporaryFile returns a file wrapper, not a pathlib.Path
        # Use os.path.exists on the file name for cleanup
        try:
            self.test_file.close()
        except Exception:
            pass
        if os.path.exists(self.test_file.name):
            os.unlink(self.test_file.name)

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_init(self, mock_ensemble, mock_extractor):
        """Test initialization."""
        config = Config()
        detector = LordofTheBrines(config)
        self.assertEqual(detector.config, config)
        mock_extractor.assert_called_once()
        mock_ensemble.assert_called_once()

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_scan_data_success(self, mock_ensemble, mock_extractor):
        """Test successful data scanning."""
        # Setup mocks
        mock_extractor.return_value.extract_features.return_value = self.sample_features
        mock_ensemble.return_value.predict.return_value = (False, 0.95, self.sample_importances)
        
        # Create detector and scan data
        detector = LordofTheBrines(self.config)
        test_data = b"test pickle data"
        result = detector.scan_data(test_data)
        
        # Assertions
        self.assertIsInstance(result, DetectionResult)
        self.assertFalse(result.is_malicious)
        self.assertEqual(result.confidence, 0.95)

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_scan_file_success(self, mock_ensemble, mock_extractor):
        """Test successful file scanning."""
        # Setup mocks
        mock_extractor.return_value.extract_features.return_value = self.sample_features
        mock_ensemble.return_value.predict.return_value = (False, 0.95, self.sample_importances)
        
        # Create detector and scan file
        detector = LordofTheBrines(self.config)
        result = detector.scan_file(self.test_file.name)
        
        # Assertions
        self.assertIsInstance(result, DetectionResult)
        self.assertEqual(result.file, self.test_file.name)
        self.assertFalse(result.is_malicious)
        self.assertEqual(result.confidence, 0.95)

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_scan_file_malicious(self, mock_ensemble, mock_extractor):
        """Test detection of malicious file."""
        # Setup mocks for malicious detection
        mock_extractor.return_value.extract_features.return_value = self.sample_features
        mock_ensemble.return_value.predict.return_value = (True, 0.98, self.sample_importances)
        
        # Create detector and scan file
        detector = LordofTheBrines(self.config)
        result = detector.scan_file(self.test_file.name)
        
        # Assertions
        self.assertIsInstance(result, DetectionResult)
        self.assertTrue(result.is_malicious)
        self.assertEqual(result.confidence, 0.98)
        self.assertEqual(result.threat_type, "Malicious")

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_file_not_found(self, mock_model_ensemble, mock_feature_extractor):
        """Test scanning a non-existent file."""
        # Create detector
        config = Config()
        detector = LordofTheBrines(config)
        
        # Test with non-existent file
        with self.assertRaises(FileNotFoundError):
            detector.scan_file("/path/to/nonexistent/file.pkl")

    @patch('extractor.FeatureExtractor')
    @patch('ensemble.ModelEnsemble')
    def test_scan_file_error_handling(self, mock_ensemble, mock_extractor):
        """Test error handling during file scanning."""
        # Setup mocks to raise exception
        mock_extractor.return_value.extract_features.side_effect = Exception("Test error")
        
        # Create detector and scan file
        detector = LordofTheBrines(self.config)
        result = detector.scan_file(self.test_file.name)
        
        # Assertions for error handling
        self.assertIsInstance(result, DetectionResult)
        self.assertFalse(result.is_malicious)  # Default to benign on error
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.threat_type, "Error")
        self.assertIn("Test error", result.explanation)


class TestContainers(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.detector = LordofTheBrines(self.config)

    def test_zip_inner_pickle(self):
        class Inner:
            def __reduce__(self):
                import os
                return (os.system, ("echo ZIP",))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('data.pkl', pkl.dumps(Inner()))
        res = self.detector.scan_data(buf.getvalue(), 'zip')
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.features.get('has_inner_pickle'))

    def test_nested_zip_inner_pickle(self):
        class Inner:
            def __reduce__(self):
                import os
                return (os.system, ("echo ZIP2",))
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w', zipfile.ZIP_DEFLATED) as oz:
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as iz:
                iz.writestr('model.pkl', pkl.dumps(Inner()))
            oz.writestr('models.zip', inner.getvalue())
        res = self.detector.scan_data(outer.getvalue(), 'zip-nested')
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.features.get('has_inner_pickle'))

    def test_tar_gz_inner_pickle(self):
        class Inner:
            def __reduce__(self):
                import os
                return (os.system, ("echo TAR",))
        inner = pkl.dumps(Inner())
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            tarb = io.BytesIO()
            with tarfile.open(fileobj=tarb, mode='w') as tf:
                info = tarfile.TarInfo('inner.pkl')
                info.size = len(inner)
                tf.addfile(info, io.BytesIO(inner))
            gz.write(tarb.getvalue())
        res = self.detector.scan_data(buf.getvalue(), 'tar.gz')
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.features.get('has_inner_pickle'))

    def test_prefixed_magic(self):
        class Inner:
            def __reduce__(self):
                import os
                return (os.system, ("echo PREF",))
        data = b"# header\n" + pkl.dumps(Inner())
        res = self.detector.scan_data(data, 'prefixed')
        self.assertTrue(res.is_malicious)


class TestEvasionHeuristics(unittest.TestCase):
    def setUp(self):
        self.detector = LordofTheBrines(Config())

    def test_pip_install_string_detected(self):
        class PipPayload:
            def __reduce__(self):
                return (eval, ("__import__('subprocess').call",))
        # Embed pip install strings in bytes
        data = pkl.dumps(PipPayload()) + b"pip install evilpkg"
        res = self.detector.scan_data(data, 'pipstr')
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.features.get('has_pip_install_string'))

    def test_marshal_usage_detected(self):
        class M:
            def __reduce__(self):
                return (eval, ("__import__('marshal').loads",))
        data = pkl.dumps(M())
        res = self.detector.scan_data(data, 'marshal')
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.features.get('has_marshal_usage'))

    def test_zip_suspicious_names(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('../evil.pkl', b'not a pickle')
        res = self.detector.scan_data(buf.getvalue(), 'zipbad')
        self.assertTrue(res.features.get('zip_suspicious_names'))


if __name__ == "__main__":
    unittest.main()
