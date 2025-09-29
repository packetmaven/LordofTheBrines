from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import json

@dataclass
class DetectionResult:
    """
    Represents the result of a pickle scan.
    """
    file: str = ""
    is_malicious: bool = False
    confidence: float = 0.0
    threat_type: str = "Unknown"
    explanation: str = ""
    feature_importances: Dict[str, float] = field(default_factory=dict)
    features: Dict[str, Any] = field(default_factory=dict)
    execution_trace: Optional[Dict[str, Any]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
    scan_time_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the DetectionResult object to a dictionary.
        """
        return {
            "file": self.file,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "threat_type": self.threat_type,
            "explanation": self.explanation,
            "feature_importances": self.feature_importances,
            "features": self.features,
            "execution_trace": self.execution_trace,
            "threat_intelligence": self.threat_intelligence,
            "scan_time_ms": self.scan_time_ms,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "DetectionResult":
        return DetectionResult(
            file=data.get("file", ""),
            is_malicious=bool(data.get("is_malicious", False)),
            confidence=float(data.get("confidence", 0.0)),
            threat_type=data.get("threat_type", "Unknown"),
            explanation=data.get("explanation", ""),
            feature_importances=dict(data.get("feature_importances", {})),
            features=dict(data.get("features", {})),
            execution_trace=data.get("execution_trace"),
            threat_intelligence=data.get("threat_intelligence"),
            scan_time_ms=data.get("scan_time_ms"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(json_str: str) -> "DetectionResult":
        return DetectionResult.from_dict(json.loads(json_str))

