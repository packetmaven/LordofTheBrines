# ![LordofTheBrines](LordoftheBrines.png)

LordofTheBrines is a security framework designed for detecting malicious Python pickle files with state-of-the-art accuracy and minimal false positives.

## Features

- **Comprehensive Pickle Analysis:** Utilizes a multi-faceted approach to analyze pickle files, including opcode analysis, structural analysis, and byte-level statistics.
  
- **Advanced Detection Algorithms:** Employs sophisticated detection algorithms and a model ensemble to accurately classify pickles as malicious or benign.
  
- **Threat Intelligence Integration:** Integrates with threat intelligence sources to enhance detection of known malicious patterns.
  
- **Behavioral Analysis (Planned):** Future capabilities will include dynamic analysis in a secure sandbox environment to detect malicious behavior.
  
- **Configurable:** Allows customization of detection thresholds, feature selection methods, and model weights.

## Installation

Currently, LordofTheBrines is a standalone framework. To use it, you can clone the repository and run the scripts directly.

```bash
git clone <repository_url> # Replace with actual repository URL if available
cd LordofTheBrines
```

## Usage

### Command Line Interface (CLI)

LordofTheBrines provides a command-line interface for scanning pickle files.

```bash
python LordofTheBrines_cli.py <path_to_pickle_file_or_directory> [options]
```

**Options:**
- `-r`, `--recursive`: Scan directories recursively.
- `-o`, `--output <file>`: Output file for scan results (e.g., `results.json`).
- `-f`, `--format <format>`: Output format (`text` or `json`). Defaults to `text`.
- `-v`, `--verbose`: Enable verbose output.

**Examples:**

Scan a single pickle file:
```bash
python LordofTheBrines_cli.py my_model.pkl
```

Scan a directory recursively and output results to a JSON file:
```bash
python LordofTheBrines_cli.py ./models --recursive --output scan_results.json --format json
```

### Programmatic Usage

You can also integrate LordofTheBrines into your Python applications:

```python
from config import Config
from detector import LordofTheBrines

# Initialize configuration
config = Config()

# Initialize the detector
detector = LordofTheBrines(config)

# Scan a pickle file
file_path = "path/to/your/pickle_file.pkl"
result = detector.scan_file(file_path)

if result.is_malicious:
    print(f"Malicious pickle detected: {file_path}")
    print(f"Confidence: {result.confidence:.2f}")
    if result.explanation:
        print(f"Explanation: {result.explanation}")
else:
    print(f"Harmless pickle: {file_path}")
    print(f"Confidence: {result.confidence:.2f}")
```

## Contributing

Contributions are welcome! Please refer to the `CONTRIBUTING.md` (if available) for guidelines on how to contribute.

## License

This project is licensed under the [MIT License](LICENSE).


