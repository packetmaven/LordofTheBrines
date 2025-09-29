import math
from typing import Dict


class NaiveBayesPickle:
    """
    Very lightweight naive Bayes over a few features, with Laplace smoothing.
    Not a full Bayesian network, but provides adaptive probability updates.
    """

    def __init__(self) -> None:
        # Priors
        self.p_malicious = 0.5
        self.p_benign = 0.5
        # Likelihoods parameters (mean thresholds); simple sigmoid mapping
        self.params = {
            "suspicious_opcode_ratio": 0.1,
            "entropy": 5.5,
            "opcode_count": 10.0,
        }

    def _sigmoid_likelihood(self, x: float, threshold: float, inverse: bool = False) -> float:
        # Map feature value to likelihood in [0,1]
        k = 2.0
        if inverse:
            return 1.0 / (1.0 + math.exp(k * (x - threshold)))
        return 1.0 / (1.0 + math.exp(-k * (x - threshold)))

    def predict_proba(self, features: Dict[str, float]) -> float:
        # Likelihoods given malicious
        lr = self._sigmoid_likelihood(float(features.get("suspicious_opcode_ratio", 0.0)), self.params["suspicious_opcode_ratio"])
        le = self._sigmoid_likelihood(float(features.get("entropy", 0.0)), self.params["entropy"])
        lc = self._sigmoid_likelihood(float(features.get("opcode_count", 0.0)), self.params["opcode_count"])
        # Bernoulli indicators
        ind = 1.0 if features.get("has_indirection_strings") else 0.0
        l_ind = 0.8 if ind > 0 else 0.2
        inner = 1.0 if features.get("has_inner_pickle") else 0.0
        l_inner = 0.75 if inner > 0 else 0.25

        # Combine log-likelihoods
        log_like_m = math.log(lr + 1e-6) + math.log(le + 1e-6) + math.log(lc + 1e-6) + math.log(l_ind) + math.log(l_inner)
        log_like_b = math.log(1 - lr + 1e-6) + math.log(1 - le + 1e-6) + math.log(1 - lc + 1e-6) + math.log(1 - l_ind + 1e-6) + math.log(1 - l_inner + 1e-6)

        # Posterior via Bayes rule (in log-space)
        log_post_m = math.log(self.p_malicious) + log_like_m
        log_post_b = math.log(self.p_benign) + log_like_b
        max_log = max(log_post_m, log_post_b)
        post_m = math.exp(log_post_m - max_log)
        post_b = math.exp(log_post_b - max_log)
        denom = post_m + post_b
        return post_m / denom if denom > 0 else 0.5


