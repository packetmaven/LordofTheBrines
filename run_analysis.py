import json
import os
from config import Config
from detector import LordofTheBrines

# Configure logging
import logging
logging.basicConfig(level=logging.INFO)

def run_analysis():
    config = Config()
    detector = LordofTheBrines(config)

    pickle_files = [
        "harmless.pkl",
        "malicious_ls.pkl",
        "malicious_touch.pkl",
        "malicious_echo.pkl",
        "malicious_subprocess_ls.pkl",
        "malicious_subprocess_touch.pkl",
    ]

    results = []
    for filename in pickle_files:
        file_path = filename
        try:
            result = detector.scan_file(file_path)
            
            # Include the filename in the dictionary before appending
            result_dict = result.to_dict()
            result_dict["file"] = filename
            results.append(result_dict)
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            results.append({"file": filename, "error": str(e)})

    with open("new_analysis_results.json", "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    run_analysis()


