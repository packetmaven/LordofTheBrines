import logging
from typing import Dict, Any, List, Optional
import os
import tempfile

logger = logging.getLogger(__name__)


DEFAULT_PATTERNS: List[bytes] = [
    b"os.system",
    b"subprocess",
    b"__import__(",
    b"getattr(__import__(",
    b"pip install",
    b"pip.main",
    b"marshal",
]


def scan_bytes(data: bytes, rules_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Optional YARA scanning. If yara-python is unavailable or no rules provided,
    fall back to fast substring patterns.
    Returns dict with: hits (list), hit_count (int), score (float 0..1)
    """
    # Try yara
    try:
        if rules_path and os.path.exists(rules_path):
            import yara  # type: ignore
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(data=data)
            names = [m.rule for m in matches]
            if names:
                score = min(1.0, len(names) / 5.0)
                return {"yara_hits": names, "yara_hit_count": len(names), "yara_score": score}
            # Compiled successfully but no matches: emulate our bundled rules to provide named hits
            emu = _emulate_picklerules(data)
            if emu:
                score = min(1.0, len(emu) / 5.0)
                return {"yara_hits": emu, "yara_hit_count": len(emu), "yara_score": score}
    except Exception as e:
        logger.debug(f"YARA scanning unavailable or failed: {e}")
        # If a rules file was provided, attempt a lightweight emulation for our bundled rules
        if rules_path and os.path.exists(rules_path):
            emu = _emulate_picklerules(data)
            if emu:
                names = emu
                score = min(1.0, len(names) / 5.0)
                return {"yara_hits": names, "yara_hit_count": len(names), "yara_score": score}

    # Fallback patterns
    hits: List[str] = []
    for pat in DEFAULT_PATTERNS:
        try:
            if pat in data:
                hits.append(pat.decode(errors='ignore') or str(pat))
        except Exception:
            continue
    score = min(1.0, len(hits) / 4.0)
    return {"yara_hits": hits, "yara_hit_count": len(hits), "yara_score": score}


def download_rules(rules_url: str, dest_path: Optional[str] = None) -> Optional[str]:
    """
    Download YARA rules from a URL and write atomically to dest_path.
    Returns the path on success, or None on failure.
    """
    try:
        import requests  # type: ignore
    except Exception:
        logger.warning("requests not installed; cannot download YARA rules")
        return None
    try:
        if dest_path is None:
            home = os.path.expanduser("~")
            cache_dir = os.path.join(home, ".lordofthebrines", "rules")
            os.makedirs(cache_dir, exist_ok=True)
            dest_path = os.path.join(cache_dir, "community.yar")
        resp = requests.get(rules_url, timeout=20)
        resp.raise_for_status()
        ddir = os.path.dirname(dest_path)
        os.makedirs(ddir, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=ddir, delete=False) as tf:
            tf.write(resp.content)
            tmp = tf.name
        os.replace(tmp, dest_path)
        logger.info(f"Downloaded YARA rules to {dest_path}")
        return dest_path
    except Exception as e:
        logger.warning(f"Failed downloading YARA rules from {rules_url}: {e}")
        return None


def _emulate_picklerules(data: bytes) -> List[str]:
    """
    Lightweight, conservative emulation of our bundled rules/pickle_rules.yar
    to provide named hits when yara-python is unavailable. This DOES NOT
    implement general YARA semantics; it only mirrors the specific patterns
    we ship and is intentionally simple and safe.
    """
    try:
        text = None
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = ''
        lower = text.lower()
        hits: List[str] = []

        # Pickle_RCE_Core_Strings (loose emulation)
        core_tokens_any = ["__import__(", "getattr(__import__(", "builtins.eval", "builtins.exec", "eval(", "exec("]
        if any(t in lower for t in core_tokens_any):
            hits.append("Pickle_RCE_Core_Strings")

        # Pickle_OS_Subprocess_Abuse
        if ("os.system" in lower) or ("subprocess" in lower) or ("sh -c" in lower):
            hits.append("Pickle_OS_Subprocess_Abuse")

        # Pickle_Marshal_Obfuscation
        if ("marshal.loads" in lower) or ("__import__('marshal')" in lower and ".loads(" in lower) or (("base64.b64decode(" in lower or "bz2.decompress(" in lower or "zlib.decompress(" in lower) and ("exec(" in lower)):
            hits.append("Pickle_Marshal_Obfuscation")

        # Pickle_Pip_Install_Evasion
        if ("pip install" in lower) or ("pip.main" in lower):
            hits.append("Pickle_Pip_Install_Evasion")

        # Pickle_Torch_Joblib_Gadget_Hints
        if (("torch.storage._load" in text) and ("torch._utils._rebuild_tensor" in text)) or (("joblib" in lower) and ("numpy.core.multiarray" in lower)):
            hits.append("Pickle_Torch_Joblib_Gadget_Hints")

        # Pickle_Unicode_ZeroWidth_Obfuscation: check raw bytes for ZWSP/ZWNJ/ZWJ/RLO
        try:
            if (b"\xE2\x80\x8B" in data) or (b"\xE2\x80\x8C" in data) or (b"\xE2\x80\x8D" in data) or (b"\xE2\x80\xAE" in data):
                hits.append("Pickle_Unicode_ZeroWidth_Obfuscation")
        except Exception:
            pass

        # Pickle_Base64_Exec_Combinator
        if ("base64.b64decode(" in lower) and ("exec(" in lower):
            hits.append("Pickle_Base64_Exec_Combinator")

        return hits
    except Exception:
        return []


