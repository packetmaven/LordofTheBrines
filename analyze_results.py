import json

with open("new_analysis_results.json", "r") as f:
    results = json.load(f)

total_files = len(results)

# Initialize counters
true_positives = 0
false_positives = 0
true_negatives = 0
false_negatives = 0

# Define the expected malicious files and harmless file
expected_malicious_files = [
    "malicious_ls.pkl",
    "malicious_touch.pkl",
    "malicious_echo.pkl",
    "malicious_subprocess_ls.pkl",
    "malicious_subprocess_touch.pkl",
]
expected_harmless_file = "harmless.pkl"

# Create a dictionary for easier lookup by filename
results_dict = {item["file"]: item for item in results}

for file_name, data in results_dict.items():
    is_malicious_predicted = data.get("is_malicious")

    if file_name == expected_harmless_file:
        # This is a harmless file
        if is_malicious_predicted:
            false_positives += 1
        else:
            true_negatives += 1
    elif file_name in expected_malicious_files:
        # This is a malicious file
        if is_malicious_predicted:
            true_positives += 1
        else:
            false_negatives += 1

print(f"Total files scanned: {total_files}")
print(f"True Positives (Malicious detected as Malicious): {true_positives}")
print(f"False Positives (Harmless detected as Malicious): {false_positives}")
print(f"True Negatives (Harmless detected as Harmless): {true_negatives}")
print(f"False Negatives (Malicious detected as Harmless): {false_negatives}")

# Calculate rates
accuracy = (true_positives + true_negatives) / total_files if total_files > 0 else 0
precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
fpr = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0

print(f"\nAccuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"False Positive Rate (FPR): {fpr:.2f}")

# Print features for harmless.pkl and one malicious pickle for comparison
print("\nFeatures for harmless.pkl:")
if expected_harmless_file in results_dict and "features" in results_dict[expected_harmless_file]:
    for feature, value in results_dict[expected_harmless_file]["features"].items():
        print(f"  {feature}: {value}")
else:
    print(f"  Features for {expected_harmless_file} not available.")

print("\nFeatures for malicious_ls.pkl:")
if "malicious_ls.pkl" in results_dict and "features" in results_dict["malicious_ls.pkl"]:
    for feature, value in results_dict["malicious_ls.pkl"]["features"].items():
        print(f"  {feature}: {value}")
else:
    print(f"  Features for malicious_ls.pkl not available.")


