"""
This module provides functionality for benchmarking the performance of the LordofTheBrines against various test cases.
"""

import os
import time
import json
import logging
import pickle
from typing import Dict, List, Any, Tuple, Optional
import matplotlib.pyplot as plt
import numpy as np

from detector import LordofTheBrines
from config import Config
from result import DetectionResult

logger = logging.getLogger("lordofthebrines.runner")


class BenchmarkRunner:
    """    
    This class provides functionality for benchmarking the performance of the LordofTheBrines against various test cases.
    
    Attributes:
        config: Configuration object for benchmarking
        detector: LordofTheBrines detector instance
        results: Dictionary of benchmark results
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the benchmark runner.
        
        Args:
            config: Configuration object for benchmarking
        """
        self.config = config or Config()
        self.detector = LordofTheBrines(self.config)
        self.results = {}
        logger.info("Initializing benchmark runner")

    def run_benchmark(self, test_dir: str, output_dir: str = None) -> Dict[str, Any]:
        """
        Run benchmarks on test cases in the specified directory.
        
        Args:
            test_dir: Directory containing test cases
            output_dir: Directory to save benchmark results
            
        Returns:
            Dictionary of benchmark results
            
        Raises:
            FileNotFoundError: If the test directory does not exist
        """
        if not os.path.exists(test_dir):
            raise FileNotFoundError(f"Test directory not found: {test_dir}")
        
        logger.info(f"Running benchmarks on test cases in {test_dir}")
        
        # Initialize results
        self.results = {
            "timestamp": time.time(),
            "config": self.config.to_dict(),
            "test_cases": {},
            "summary": {},
        }
        
        # Find test cases
        benign_dir = os.path.join(test_dir, "benign")
        malicious_dir = os.path.join(test_dir, "malicious")
        
        # Process benign test cases
        benign_results = self._process_test_cases(benign_dir, expected_malicious=False)
        self.results["test_cases"]["benign"] = benign_results
        
        # Process malicious test cases
        malicious_results = self._process_test_cases(malicious_dir, expected_malicious=True)
        self.results["test_cases"]["malicious"] = malicious_results
        
        # Calculate summary statistics
        self._calculate_summary()
        
        # Save results if output directory is specified
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
            # Save results as JSON
            results_path = os.path.join(output_dir, "benchmark_results.json")
            with open(results_path, "w") as f:
                json.dump(self.results, f, indent=2)
            
            # Generate and save plots
            self._generate_plots(output_dir)
        
        return self.results

    def _process_test_cases(self, test_dir: str, expected_malicious: bool) -> List[Dict[str, Any]]:
        """
        Process test cases in the specified directory.
        
        Args:
            test_dir: Directory containing test cases
            expected_malicious: Whether the test cases are expected to be malicious
            
        Returns:
            List of test case results
        """
        results = []
        
        if not os.path.exists(test_dir):
            logger.warning(f"Test directory not found: {test_dir}")
            return results
        
        logger.info(f"Processing test cases in {test_dir}")
        
        # Process each file in the directory
        for filename in os.listdir(test_dir):
            if filename.endswith((".pkl", ".pickle")):
                file_path = os.path.join(test_dir, filename)
                
                try:
                    # Scan the file
                    start_time = time.time()
                    result = self.detector.scan_file(file_path)
                    scan_time = time.time() - start_time
                    
                    # Check if the result matches the expected outcome
                    correct = result.is_malicious == expected_malicious
                    
                    # Record the result
                    test_result = {
                        "file": filename,
                        "expected_malicious": expected_malicious,
                        "detected_malicious": result.is_malicious,
                        "confidence": result.confidence,
                        "scan_time": scan_time,
                        "correct": correct,
                    }
                    
                    if result.threat_type:
                        test_result["threat_type"] = result.threat_type
                    
                    results.append(test_result)
                    
                    logger.debug(f"Processed {filename}: correct={correct}, confidence={result.confidence:.2f}")
                    
                except Exception as e:
                    logger.error(f"Error processing {filename}: {e}")
                    
                    # Record the error
                    results.append({
                        "file": filename,
                        "expected_malicious": expected_malicious,
                        "error": str(e),
                        "correct": False,
                    })
        
        return results

    def _calculate_summary(self) -> None:
        """Calculate summary statistics for benchmark results."""
        summary = {}
        
        # Get test case results
        benign_results = self.results["test_cases"].get("benign", [])
        malicious_results = self.results["test_cases"].get("malicious", [])
        
        # Calculate true positives, false positives, true negatives, false negatives
        tp = sum(1 for r in malicious_results if r.get("detected_malicious", False))
        fp = sum(1 for r in benign_results if r.get("detected_malicious", False))
        tn = sum(1 for r in benign_results if not r.get("detected_malicious", True))
        fn = sum(1 for r in malicious_results if not r.get("detected_malicious", True))
        
        # Calculate metrics
        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Calculate timing statistics
        benign_times = [r.get("scan_time", 0) for r in benign_results if "scan_time" in r]
        malicious_times = [r.get("scan_time", 0) for r in malicious_results if "scan_time" in r]
        all_times = benign_times + malicious_times
        
        avg_time = sum(all_times) / len(all_times) if all_times else 0
        max_time = max(all_times) if all_times else 0
        min_time = min(all_times) if all_times else 0
        
        # Store summary statistics
        summary["total_test_cases"] = total
        summary["benign_test_cases"] = len(benign_results)
        summary["malicious_test_cases"] = len(malicious_results)
        
        summary["true_positives"] = tp
        summary["false_positives"] = fp
        summary["true_negatives"] = tn
        summary["false_negatives"] = fn
        
        summary["accuracy"] = accuracy
        summary["precision"] = precision
        summary["recall"] = recall
        summary["f1_score"] = f1_score
        summary["false_positive_rate"] = false_positive_rate
        summary["false_negative_rate"] = false_negative_rate
        
        summary["avg_scan_time"] = avg_time
        summary["max_scan_time"] = max_time
        summary["min_scan_time"] = min_time
        
        # Store summary in results
        self.results["summary"] = summary
        
        # Log summary
        logger.info(f"Benchmark summary: accuracy={accuracy:.4f}, precision={precision:.4f}, recall={recall:.4f}, f1_score={f1_score:.4f}")
        logger.info(f"False positive rate: {false_positive_rate:.4f}, False negative rate: {false_negative_rate:.4f}")
        logger.info(f"Average scan time: {avg_time:.4f}s")

    def _generate_plots(self, output_dir: str) -> None:
        """
        Generate and save plots for benchmark results.
        
        Args:
            output_dir: Directory to save plots
        """
        try:
            # Create plots directory
            plots_dir = os.path.join(output_dir, "plots")
            os.makedirs(plots_dir, exist_ok=True)
            
            # Get test case results
            benign_results = self.results["test_cases"].get("benign", [])
            malicious_results = self.results["test_cases"].get("malicious", [])
            
            # Plot confidence distribution
            self._plot_confidence_distribution(
                benign_results, malicious_results,
                os.path.join(plots_dir, "confidence_distribution.png")
            )
            
            # Plot ROC curve
            self._plot_roc_curve(
                benign_results, malicious_results,
                os.path.join(plots_dir, "roc_curve.png")
            )
            
            # Plot scan time distribution
            self._plot_scan_time_distribution(
                benign_results, malicious_results,
                os.path.join(plots_dir, "scan_time_distribution.png")
            )
            
            # Plot confusion matrix
            self._plot_confusion_matrix(
                self.results["summary"],
                os.path.join(plots_dir, "confusion_matrix.png")
            )
            
            logger.info(f"Generated plots in {plots_dir}")
            
        except Exception as e:
            logger.error(f"Error generating plots: {e}")

    def _plot_confidence_distribution(self, benign_results: List[Dict[str, Any]], 
                                     malicious_results: List[Dict[str, Any]], 
                                     output_path: str) -> None:
        """
        Plot confidence distribution for benign and malicious test cases.
        
        Args:
            benign_results: List of benign test case results
            malicious_results: List of malicious test case results
            output_path: Path to save the plot
        """
        plt.figure(figsize=(10, 6))
        
        # Get confidence values
        benign_confidences = [r.get("confidence", 0) for r in benign_results if "confidence" in r]
        malicious_confidences = [r.get("confidence", 0) for r in malicious_results if "confidence" in r]
        
        # Plot histograms
        plt.hist(benign_confidences, bins=20, alpha=0.5, label="Benign", color="green")
        plt.hist(malicious_confidences, bins=20, alpha=0.5, label="Malicious", color="red")
        
        # Add threshold line
        threshold = self.config.detection_threshold
        plt.axvline(x=threshold, color="black", linestyle="--", label=f"Threshold ({threshold})")
        
        # Add labels and legend
        plt.xlabel("Confidence Score")
        plt.ylabel("Number of Test Cases")
        plt.title("Confidence Score Distribution")
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save plot
        plt.savefig(output_path)
        plt.close()

    def _plot_roc_curve(self, benign_results: List[Dict[str, Any]], 
                       malicious_results: List[Dict[str, Any]], 
                       output_path: str) -> None:
        """
        Plot ROC curve for benchmark results.
        
        Args:
            benign_results: List of benign test case results
            malicious_results: List of malicious test case results
            output_path: Path to save the plot
        """
        plt.figure(figsize=(8, 8))
        
        # Get confidence values
        benign_confidences = [r.get("confidence", 0) for r in benign_results if "confidence" in r]
        malicious_confidences = [r.get("confidence", 0) for r in malicious_results if "confidence" in r]
        
        # Calculate ROC curve
        thresholds = np.linspace(0, 1, 100)
        tpr = []  # True positive rate
        fpr = []  # False positive rate
        
        for threshold in thresholds:
            tp = sum(1 for c in malicious_confidences if c >= threshold)
            fp = sum(1 for c in benign_confidences if c >= threshold)
            tn = sum(1 for c in benign_confidences if c < threshold)
            fn = sum(1 for c in malicious_confidences if c < threshold)
            
            tpr.append(tp / (tp + fn) if (tp + fn) > 0 else 0)
            fpr.append(fp / (fp + tn) if (fp + tn) > 0 else 0)
        
        # Calculate AUC
        auc = np.trapz(tpr, fpr)
        
        # Plot ROC curve
        plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {auc:.4f})")
        
        # Add diagonal line
        plt.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random Guess")
        
        # Add current threshold point
        threshold_idx = np.abs(thresholds - self.config.detection_threshold).argmin()
        plt.scatter(fpr[threshold_idx], tpr[threshold_idx], color="red", 
                   label=f"Current Threshold ({self.config.detection_threshold})")
        
        # Add labels and legend
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("Receiver Operating Characteristic (ROC) Curve")
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Set equal aspect ratio
        plt.axis("square")
        plt.xlim([0, 1])
        plt.ylim([0, 1])
        
        # Save plot
        plt.savefig(output_path)
        plt.close()

    def _plot_scan_time_distribution(self, benign_results: List[Dict[str, Any]], 
                                    malicious_results: List[Dict[str, Any]], 
                                    output_path: str) -> None:
        """
        Plot scan time distribution for benign and malicious test cases.
        
        Args:
            benign_results: List of benign test case results
            malicious_results: List of malicious test case results
            output_path: Path to save the plot
        """
        plt.figure(figsize=(10, 6))
        
        # Get scan times
        benign_times = [r.get("scan_time", 0) for r in benign_results if "scan_time" in r]
        malicious_times = [r.get("scan_time", 0) for r in malicious_results if "scan_time" in r]
        
        # Plot histograms
        plt.hist(benign_times, bins=20, alpha=0.5, label="Benign", color="green")
        plt.hist(malicious_times, bins=20, alpha=0.5, label="Malicious", color="red")
        
        # Add labels and legend
        plt.xlabel("Scan Time (seconds)")
        plt.ylabel("Number of Test Cases")
        plt.title("Scan Time Distribution")
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save plot
        plt.savefig(output_path)
        plt.close()

    def _plot_confusion_matrix(self, summary: Dict[str, Any], output_path: str) -> None:
        """
        Plot confusion matrix for benchmark results.
        
        Args:
            summary: Summary statistics from benchmark results
            output_path: Path to save the plot
        """
        plt.figure(figsize=(8, 6))
        
        # Get confusion matrix values
        tp = summary.get("true_positives", 0)
        fp = summary.get("false_positives", 0)
        tn = summary.get("true_negatives", 0)
        fn = summary.get("false_negatives", 0)
        
        # Create confusion matrix
        cm = np.array([[tn, fp], [fn, tp]])
        
        # Plot confusion matrix
        plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        plt.title("Confusion Matrix")
        plt.colorbar()
        
        # Add labels
        classes = ["Benign", "Malicious"]
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes)
        plt.yticks(tick_marks, classes)
        
        # Add text annotations
        thresh = cm.max() / 2.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(j, i, format(cm[i, j], "d"),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        
        plt.xlabel("Predicted Label")
        plt.ylabel("True Label")
        plt.tight_layout()
        
        # Save plot
        plt.savefig(output_path)
        plt.close()


def create_test_data(output_dir: str, num_benign: int = 10, num_malicious: int = 10) -> None:
    """
    Create test data for benchmarking.
    
    Args:
        output_dir: Directory to save test data
        num_benign: Number of benign test cases to create
        num_malicious: Number of malicious test cases to create
    """
    # Create output directories
    benign_dir = os.path.join(output_dir, "benign")
    malicious_dir = os.path.join(output_dir, "malicious")
    
    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)
    
    # Create benign test cases
    for i in range(num_benign):
        # Create a simple benign pickle
        data = {
            "name": f"benign_data_{i}",
            "value": i,
            "data": [1, 2, 3, 4, 5],
            "nested": {"a": 1, "b": 2},
        }
        
        # Save to file
        file_path = os.path.join(benign_dir, f"benign_{i}.pkl")
        with open(file_path, "wb") as f:
            pickle.dump(data, f)
    
    # Create malicious test cases
    for i in range(num_malicious):
        # Create a pickle with suspicious patterns
        if i % 3 == 0:
            # Command execution pattern
            class Evil:
                def __reduce__(self):
                    return (os.system, ("echo 'Evil code executed'",))
            
            data = Evil()
        elif i % 3 == 1:
            # File access pattern
            class Evil:
                def __reduce__(self):
                    return (open, ("/etc/passwd", "r"))
            
            data = Evil()
        else:
            # Import suspicious module pattern
            data = {
                "name": f"malicious_data_{i}",
                "value": i,
                "module": __import__("os"),
                "subprocess": __import__("subprocess"),
            }
        
        # Save to file
        file_path = os.path.join(malicious_dir, f"malicious_{i}.pkl")
        with open(file_path, "wb") as f:
            pickle.dump(data, f)


if __name__ == "__main__":
    import argparse
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Benchmark LordofTheBrines")
    parser.add_argument("--test-dir", default="test_data", help="Directory containing test data")
    parser.add_argument("--output-dir", default="benchmark_results", help="Directory to save benchmark results")
    parser.add_argument("--create-test-data", action="store_true", help="Create test data")
    parser.add_argument("--num-benign", type=int, default=10, help="Number of benign test cases to create")
    parser.add_argument("--num-malicious", type=int, default=10, help="Number of malicious test cases to create")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create test data if requested
    if args.create_test_data:
        create_test_data(args.test_dir, args.num_benign, args.num_malicious)
        print(f"Created test data in {args.test_dir}")
    
    # Run benchmark
    runner = BenchmarkRunner()
    results = runner.run_benchmark(args.test_dir, args.output_dir)
    
    # Print summary
    summary = results["summary"]
    print("\nBenchmark Summary:")
    print(f"Total test cases: {summary['total_test_cases']}")
    print(f"Accuracy: {summary['accuracy']:.4f}")
    print(f"Precision: {summary['precision']:.4f}")
    print(f"Recall: {summary['recall']:.4f}")
    print(f"F1 Score: {summary['f1_score']:.4f}")
    print(f"False Positive Rate: {summary['false_positive_rate']:.4f}")
    print(f"False Negative Rate: {summary['false_negative_rate']:.4f}")
    print(f"Average Scan Time: {summary['avg_scan_time']:.4f}s")
    print(f"\nResults saved to {args.output_dir}")
