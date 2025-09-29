# Core API

## ![LordofTheBrines](LordoftheBrines.png)

The main class for detecting malicious pickle files.

```python
from detector import LordofTheBrines

# Initialize with default configuration
detector = LordofTheBrines()

# Initialize with custom configuration
from config import Config
config = Config()
config.detection_threshold = 0.9
detector = LordofTheBrines(config)
```

### Methods

#### scan_file(file_path)
Scan a pickle file for malicious content.

```python
result = detector.scan_file("/path/to/file.pkl")
```

Parameters:
- `file_path` (str): Path to the pickle file to scan

Returns:
- `DetectionResult`: Object containing scan results

Raises:
- `FileNotFoundError`: If the file does not exist
- `PermissionError`: If the file cannot be read
- `ValueError`: If the file is not a valid pickle

#### scan_data(pickle_data)
Scan pickle data for malicious content.

```python
with open("file.pkl", "rb") as f:
    data = f.read()
result = detector.scan_data(data)
```

Parameters:
- `pickle_data` (bytes): Pickle data as bytes

Returns:
- `DetectionResult`: Object containing scan results

Raises:
- `ValueError`: If the data is not valid pickle data

#### scan_file_object(file_obj)
Scan a file object containing pickle data.

```python
with open("file.pkl", "rb") as f:
    result = detector.scan_file_object(f)
```

Parameters:
- `file_obj` (BinaryIO): File object opened in binary mode

Returns:
- `DetectionResult`: Object containing scan results

Raises:
- `ValueError`: If the data is not valid pickle data

#### scan_directory(directory_path, recursive=False)
Scan all pickle files in a directory.

```python
results = detector.scan_directory("/path/to/directory", recursive=True)
```

Parameters:
- `directory_path` (str): Path to the directory to scan
- `recursive` (bool): Whether to scan subdirectories recursively

Returns:
- `Dict[str, DetectionResult]`: Dictionary mapping file paths to DetectionResult objects

Raises:
- `FileNotFoundError`: If the directory does not exist
- `PermissionError`: If the directory cannot be read

## Config

Configuration class for LordofTheBrines.

```python
from config import Config

# Create with default values
config = Config()

# Modify configuration
config.detection_threshold = 0.9
config.enable_behavioral_analysis = True

# Load from file
config = Config.from_file("/path/to/config.json")

# Create from dictionary
config_dict = {
    "detection_threshold": 0.9,
    "enable_behavioral_analysis": True
}
config = Config.from_dict(config_dict)
```

### Attributes

- `detection_threshold` (float): Threshold for malicious detection (0.0-1.0)
- `log_level` (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `feature_selection_method` (str): Method for feature selection
- `enable_behavioral_analysis` (bool): Whether to enable behavioral analysis
- `enable_threat_intelligence` (bool): Whether to enable threat intelligence
- `custom_model_path` (str): Path to custom model file
- `model_ensemble_weights` (Dict[str, float]): Weights for model ensemble
- `threat_intelligence_sources` (List[str]): List of threat intelligence sources

### Methods

#### from_file(file_path)
Load configuration from a JSON file.

```python
config = Config.from_file("/path/to/config.json")
```

Parameters:
- `file_path` (str): Path to the configuration file

Returns:
- `Config`: Configuration object with settings from the file

Raises:
- `FileNotFoundError`: If the file does not exist
- `ValueError`: If the file is not valid JSON

#### from_dict(config_dict)
Create configuration from a dictionary.

```python
config_dict = {
    "detection_threshold": 0.9,
    "enable_behavioral_analysis": True
}
config = Config.from_dict(config_dict)
```

Parameters:
- `config_dict` (Dict[str, Any]): Dictionary of configuration settings

Returns:
- `Config`: Configuration object with settings from the dictionary

#### to_dict()
Convert configuration to dictionary.

```python
config_dict = config.to_dict()
```

Returns:
- `Dict[str, Any]`: Dictionary of configuration settings

#### to_json()
Convert configuration to JSON string.

```python
json_str = config.to_json()
```

Returns:
- `str`: JSON string of configuration settings

#### save_to_file(file_path)
Save configuration to a JSON file.

```python
config.save_to_file("/path/to/config.json")
```

Parameters:
- `file_path` (str): Path to the output file

Raises:
- `PermissionError`: If the file cannot be written

## DetectionResult

Class representing the result of a pickle file analysis.

```python
from result import DetectionResult

# Create a detection result
result = DetectionResult(is_malicious=True, confidence=0.95)

# Access attributes
if result.is_malicious:
    print(f"Malicious pickle detected! {result.threat_type}")
    print(f"Explanation: {result.explanation}")
    print(f"Confidence: {result.confidence}")
```

### Attributes

- `is_malicious` (bool): Whether the pickle is detected as malicious
- `confidence` (float): Confidence score of the detection (0.0-1.0)
- `threat_type` (Optional[str]): Type of threat detected (if malicious)
- `explanation` (Optional[str]): Human-readable explanation of the detection
- `feature_importances` (Dict[str, float]): Dictionary of feature importances for the detection
- `execution_trace` (Optional[List[Dict[str, Any]]]): List of execution events from behavioral analysis
- `threat_intelligence` (Optional[Dict[str, Any]]): Information from threat intelligence sources
- `scan_time_ms` (Optional[float]): Time taken for the scan in milliseconds

### Methods

#### to_dict()
Convert detection result to dictionary.

```python
result_dict = result.to_dict()
```

Returns:
- `Dict[str, Any]`: Dictionary of detection result attributes

#### to_json()
Convert detection result to JSON string.

```python
json_str = result.to_json()
```

Returns:
- `str`: JSON string of detection result attributes

#### from_dict(result_dict)
Create detection result from dictionary.

```python
result_dict = {
    "is_malicious": True,
    "confidence": 0.95,
    "threat_type": "Command Execution"
}
result = DetectionResult.from_dict(result_dict)
```

Parameters:
- `result_dict` (Dict[str, Any]): Dictionary of detection result attributes

Returns:
- `DetectionResult`: Detection result object with attributes from the dictionary

#### from_json(json_str)
Create detection result from JSON string.

```python
json_str = '{"is_malicious": true, "confidence": 0.95}'
result = DetectionResult.from_json(json_str)
```

Parameters:
- `json_str` (str): JSON string of detection result attributes

Returns:
- `DetectionResult`: Detection result object with attributes from the JSON string

# Advanced API

## BehavioralAnalyzer

Analyze pickle files in a secure sandbox environment.

```python
from analyzer import BehavioralAnalyzer
from config import Config

config = Config()
analyzer = BehavioralAnalyzer(config)

# Analyze pickle data
with open("file.pkl", "rb") as f:
    data = f.read()
events = analyzer.analyze(data)
```

### Methods

#### analyze(pickle_data)
Analyze pickle data in a secure sandbox environment.

```python
events = analyzer.analyze(pickle_data)
```

Parameters:
- `pickle_data` (bytes): Pickle data as bytes

Returns:
- `List[Dict[str, Any]]`: List of execution events with behavior information

## ThreatIntelligenceProvider

Provide threat intelligence for pickle security detection.

```python
from provider import ThreatIntelligenceProvider
from config import Config

config = Config()
provider = ThreatIntelligenceProvider(config)

# Look up threat intelligence
intel = provider.lookup(features)
```

### Methods

#### lookup(features)
Look up threat intelligence for the given features.

```python
intel = provider.lookup(features)
```

Parameters:
- `features` (Dict[str, Any]): Extracted features from pickle data

Returns:
- `Optional[Dict[str, Any]]`: Dictionary of threat intelligence information, or None if no match

## FeatureExtractor

Extract features from pickle data for malicious pickle detection.

```python
from extractor import FeatureExtractor
from config import Config

config = Config()
extractor = FeatureExtractor(config)

# Extract features
with open("file.pkl", "rb") as f:
    data = f.read()
features = extractor.extract(data)
```

### Methods

#### extract(pickle_data)
Extract features from pickle data.

```python
features = extractor.extract(pickle_data)
```

Parameters:
- `pickle_data` (bytes): Pickle data as bytes

Returns:
- `Dict[str, Any]`: Dictionary of extracted features

Raises:
- `ValueError`: If the data is not valid pickle data

## ModelEnsemble

Ensemble of detection models for malicious pickle detection.

```python
from ensemble import ModelEnsemble
from config import Config

config = Config()
ensemble = ModelEnsemble(config)

# Make prediction
prediction, confidence, feature_importances = ensemble.predict(features)
```

### Methods

#### predict(features)
Make a prediction using the model ensemble.

```python
prediction, confidence, feature_importances = ensemble.predict(features)
```

Parameters:
- `features` (Dict[str, Any]): Dictionary of extracted features

Returns:
- `Tuple[bool, float, Dict[str, float]]`: Tuple of (is_malicious, confidence, feature_importances)

Raises:
- `ValueError`: If no models are available

# Command Line Interface

LordofTheBrines provides a command-line interface for scanning pickle files.

```bash
lordofthebrines [options] [input]
```

## Options

### Basic Options
- `input`: Path to pickle file or directory to scan (defaults to current directory)
- `-r, --recursive`: Scan directories recursively
- `-o, --output <file>`: Output file for scan results (e.g., results.json)
- `-f, --format <format>`: Output format (text or json). Defaults to text
- `-v, --verbose`: Enable verbose output

### Advanced Analysis Options
- `-b, --behavioral, --enable-behavioral-analysis`: Enable behavioral analysis in secure sandbox environment
- `-i, --threat-intelligence, --enable-threat-intelligence`: Enable threat intelligence integration
- `-t, --threshold <value>`: Detection threshold (0.0-1.0). Lower = more sensitive. Default: 0.8
- `--max-analysis`: Enable all advanced analysis features (behavioral + threat intelligence + sensitive threshold)

## Examples

Scan a single file:
```bash
python LordofTheBrines_cli.py file.pkl
```

Scan a directory recursively:
```bash
python LordofTheBrines_cli.py --recursive /path/to/directory
```

Maximum security scan with all advanced features:
```bash
python LordofTheBrines_cli.py --max-analysis --verbose --recursive --format json --output security_report.json /path/to/scan
```

Custom sensitive analysis:
```bash
python LordofTheBrines_cli.py --behavioral --threat-intelligence --threshold 0.6 --format json suspicious_file.pkl
```

Production validation with conservative threshold:
```bash
python LordofTheBrines_cli.py --threat-intelligence --threshold 0.95 model.pkl
```

Save results to a JSON file:
```bash
python LordofTheBrines_cli.py --output results.json --format json file.pkl
```
