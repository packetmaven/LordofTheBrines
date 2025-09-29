import logging
import pickletools
import io
import zipfile
from collections import Counter, OrderedDict
from typing import Dict, Any
import hashlib
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """
    Extracts various features from pickle byte streams.
    """
    def __init__(self, config):
        self.config = config
        logger.info("Initializing feature extractor")
        # Simple bounded LRU cache for features keyed by sha256
        self._feature_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def extract_features(self, data: bytes) -> Dict[str, Any]:
        features = {}
        
        # Basic file properties
        features["file_size"] = len(data)
        features["md5_hash"] = self._calculate_hash(data, "md5")
        features["sha256_hash"] = self._calculate_hash(data, "sha256")

        # Memoization: if enabled, use LRU cache keyed by sha256 for expensive subroutines
        if getattr(self.config, 'enable_feature_cache', True):
            try:
                return self._extract_features_cached(data)
            except Exception:
                # Fallback to non-cached path
                pass

        # Check cache after hashing
        cache_enabled = getattr(self.config, 'enable_feature_cache', True)
        cache_size = int(getattr(self.config, 'feature_cache_size', 2048)) or 2048

        cache_key = features["sha256_hash"]
        if cache_enabled:
            cached = self._feature_cache.get(cache_key)
            if cached is not None:
                # Move to end (most-recent)
                self._feature_cache.move_to_end(cache_key)
                return dict(cached)

        # Opcode-based features
        opcode_features = self._extract_opcode_features(data)
        features.update(opcode_features)

        # Structural features
        structural_features = self._extract_structural_features(data)
        features.update(structural_features)

        # Entropy and byte-level features
        byte_features = self._extract_byte_features(data)
        features.update(byte_features)

        # Indirection string heuristics (eval/__import__/getattr)
        indirection_features = self._extract_indirection_strings(data)
        features.update(indirection_features)

        # Obfuscation signatures (builtins.*, base64-encoded suspicious tokens)
        obfuscation_features = self._extract_obfuscation_signatures(data)
        features.update(obfuscation_features)

        # Advanced evasion indicators (pip/marshal/joblib/zip tamper)
        evasion_features = self._extract_evasion_indicators(data)
        features.update(evasion_features)

        # Framework-specific signatures (Torch, etc.)
        framework_features = self._extract_framework_signatures(data)
        features.update(framework_features)

        # Compression ratio
        features["compression_ratio"] = self._calculate_compression_ratio(data)

        # Check for suspicious modules/functions (dynamic analysis simulation)
        features["has_suspicious_modules"] = self._check_suspicious_modules(data)
        features["has_suspicious_functions"] = self._check_suspicious_functions(data)

        # Store in cache
        if cache_enabled:
            try:
                self._feature_cache[cache_key] = dict(features)
                self._feature_cache.move_to_end(cache_key)
                while len(self._feature_cache) > cache_size:
                    self._feature_cache.popitem(last=False)
            except Exception:
                pass
        return features

    def _calculate_hash(self, data: bytes, hash_type: str) -> str:
        if hash_type == "md5":
            return hashlib.md5(data).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(data).hexdigest()
        return ""

    def _cache_key(self, data: bytes) -> str:
        # Only sha256 is used for the cache key
        return hashlib.sha256(data).hexdigest()

    def _maybe_parallel(self) -> ThreadPoolExecutor:
        if getattr(self.config, 'enable_parallel_archive_scanning', True):
            max_workers = int(getattr(self.config, 'max_parallel_workers', 4))
            return ThreadPoolExecutor(max_workers=max_workers)
        # Single-thread dummy executor context
        return ThreadPoolExecutor(max_workers=1)

    @lru_cache(maxsize=256)
    def _extract_features_cached(self, data: bytes) -> Dict[str, Any]:
        # lru_cache on bytes is allowed but can be memory heavy; size kept small
        # This function mirrors extract_features body but without the early cache check
        features: Dict[str, Any] = {}
        features["file_size"] = len(data)
        features["md5_hash"] = hashlib.md5(data).hexdigest()
        features["sha256_hash"] = hashlib.sha256(data).hexdigest()

        opcode_features = self._extract_opcode_features(data)
        features.update(opcode_features)

        structural_features = self._extract_structural_features(data)
        features.update(structural_features)

        byte_features = self._extract_byte_features(data)
        features.update(byte_features)

        indirection_features = self._extract_indirection_strings(data)
        features.update(indirection_features)

        obfuscation_features = self._extract_obfuscation_signatures(data)
        features.update(obfuscation_features)

        evasion_features = self._extract_evasion_indicators(data)
        features.update(evasion_features)

        framework_features = self._extract_framework_signatures(data)
        features.update(framework_features)

        features["compression_ratio"] = self._calculate_compression_ratio(data)

        features["has_suspicious_modules"] = self._check_suspicious_modules(data)
        features["has_suspicious_functions"] = self._check_suspicious_functions(data)
        return features

    def _extract_opcode_features(self, data: bytes) -> Dict[str, Any]:
        features = {}
        try:
            # Use pickletools.genops to get opcode information
            # If this fails (e.g., prefixed data), we'll try scanning for protocol magic offsets.
            disassembly = list(pickletools.genops(data))
            # Heuristic: also scan for inner pickle payloads starting at protocol magic
            # and take the largest disassembly result.
            best = disassembly
            for magic in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                start = 0
                while True:
                    idx = data.find(magic, start)
                    if idx == -1:
                        break
                    start = idx + 1
                    try:
                        alt = list(pickletools.genops(data[idx:]))
                        if len(alt) > len(best):
                            best = alt
                    except Exception:
                        continue
            disassembly = best
            
            opcode_counts = Counter()
            suspicious_opcodes = set(self.config.suspicious_opcodes)
            total_opcodes = 0
            suspicious_opcode_count = 0

            for opcode, arg, pos in disassembly:
                opcode_counts[opcode.name] += 1
                total_opcodes += 1
                if opcode.name in suspicious_opcodes:
                    suspicious_opcode_count += 1

            features["opcode_count"] = total_opcodes
            features["suspicious_opcode_count"] = suspicious_opcode_count
            features["suspicious_opcode_ratio"] = suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0

            # Add counts for specific opcodes
            for opcode_name, count in opcode_counts.items():
                features[f"opcode_{opcode_name}"] = count

        except Exception as e:
            logger.debug(f"Error extracting opcode features: {e}")
            # Second-chance: scan for protocol magic offsets in arbitrary data (prefixed tails)
            try:
                best = []
                for magic in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                    start = 0
                    while True:
                        idx = data.find(magic, start)
                        if idx == -1:
                            break
                        start = idx + 1
                        try:
                            alt = list(pickletools.genops(data[idx:]))
                            if len(alt) > len(best):
                                best = alt
                        except Exception:
                            continue
                if best:
                    opcode_counts = Counter()
                    suspicious_opcodes = set(self.config.suspicious_opcodes)
                    total_opcodes = 0
                    suspicious_opcode_count = 0
                    for opcode, arg, pos in best:
                        opcode_counts[opcode.name] += 1
                        total_opcodes += 1
                        if opcode.name in suspicious_opcodes:
                            suspicious_opcode_count += 1
                    features["opcode_count"] = total_opcodes
                    features["suspicious_opcode_count"] = suspicious_opcode_count
                    features["suspicious_opcode_ratio"] = (
                        suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0
                    )
                    for opcode_name, count in opcode_counts.items():
                        features[f"opcode_{opcode_name}"] = count
                    # Return early since we successfully parsed a tail pickle
                    return features
            except Exception:
                pass
            # Fallback: Some frameworks (e.g., TorchScript .pt) store pickles inside ZIP.
            try:
                if getattr(self.config, 'enable_zip_scanning', True) and len(data) > 4 and data[:2] == b'PK':
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        names = zf.namelist()
                        # ZIP metadata checks (CVE-2025-1944/1945 classes)
                        try:
                            suspicious_names = any(
                                n.strip().lower() in {"..", ".", "", "nul", "con"} or n.startswith(('/','\\')) or ('..' in n)
                                for n in names
                            )
                            features["zip_suspicious_names"] = bool(suspicious_names)
                            # Check general purpose bit flags for unsupported features
                            suspicious_flags = False
                            for zi in zf.infolist():
                                # Bits like 0x08 (data descriptor) and unusual combos can be abused; flag non-zero high bits
                                if zi.flag_bits & 0xFFF0:
                                    suspicious_flags = True
                                    break
                            features["zip_suspicious_flags"] = bool(suspicious_flags)
                        except Exception:
                            pass
                        # Prefer common pickle payload names first
                        candidate_names = []
                        for preferred in ("data.pkl", "pickle", "model.pkl"):
                            if preferred in names:
                                candidate_names.append(preferred)
                        candidate_names.extend([n for n in names if n.endswith((".pkl", ".pickle"))])
                        # Deduplicate while preserving order
                        seen = set()
                        ordered = []
                        for n in candidate_names:
                            if n not in seen:
                                ordered.append(n)
                                seen.add(n)
                        # Optionally parallelize scanning of candidate inner pickles
                        def _scan_inner(name: str) -> Dict[str, Any]:
                            out: Dict[str, Any] = {}
                            try:
                                inner = zf.read(name)
                                # Try direct disassembly; on failure, scan for protocol magic offsets
                                try:
                                    disassembly = list(pickletools.genops(inner))
                                except Exception:
                                    best_inner = []
                                    for magic2 in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                                        s2 = 0
                                        while True:
                                            j = inner.find(magic2, s2)
                                            if j == -1:
                                                break
                                            s2 = j + 1
                                            try:
                                                alt2 = list(pickletools.genops(inner[j:]))
                                                if len(alt2) > len(best_inner):
                                                    best_inner = alt2
                                            except Exception:
                                                continue
                                    if best_inner:
                                        disassembly = best_inner
                                    else:
                                        raise
                                opcode_counts = Counter()
                                suspicious_opcodes = set(self.config.suspicious_opcodes)
                                total_opcodes = 0
                                suspicious_opcode_count = 0
                                for opcode, arg, pos in disassembly:
                                    opcode_counts[opcode.name] += 1
                                    total_opcodes += 1
                                    if opcode.name in suspicious_opcodes:
                                        suspicious_opcode_count += 1
                                out["opcode_count"] = total_opcodes
                                out["suspicious_opcode_count"] = suspicious_opcode_count
                                out["suspicious_opcode_ratio"] = (
                                    suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0
                                )
                                for opcode_name, count in opcode_counts.items():
                                    out[f"opcode_{opcode_name}"] = count
                                out["has_inner_pickle"] = True
                                out["container_type"] = "zip"
                                # structural heuristics for inner
                                try:
                                    if b'__reduce__' in inner or b'__setstate__' in inner:
                                        out["has_functions"] = True
                                    if b'import' in inner or b'os.system' in inner or b'subprocess' in inner:
                                        out["has_modules"] = True
                                except Exception:
                                    pass
                            except Exception:
                                try:
                                    out["has_pickle_name_only"] = True
                                    out["container_type"] = "zip"
                                except Exception:
                                    pass
                            return out

                        if getattr(self.config, 'enable_parallel_archive_scanning', True):
                            with self._maybe_parallel() as pool:
                                futs = {pool.submit(_scan_inner, name): name for name in ordered}
                                for fut in as_completed(futs):
                                    res = fut.result()
                                    # Prefer the first successful inner pickle disassembly result
                                    if res.get("has_inner_pickle"):
                                        features.update(res)
                                        return features
                                    # Otherwise merge weak signals conservatively
                                    if res.get("has_pickle_name_only") and not features.get("has_pickle_name_only"):
                                        features.update(res)
                                # Do not return here; fall through to nested zip scanning
                        else:
                            for name in ordered:
                                res = _scan_inner(name)
                                if res.get("has_inner_pickle"):
                                    features.update(res)
                                    return features
                                if res.get("has_pickle_name_only") and not features.get("has_pickle_name_only"):
                                    features.update(res)
                            # Do not return here; fall through to nested zip scanning
                        # Limited nested ZIP support: search inner zips for embedded pickles
                        if getattr(self.config, 'enable_nested_zip_scanning', True):
                            # Mark presence of nested zip containers
                            try:
                                if any(n.lower().endswith((".zip", ".pt", ".pth")) for n in names):
                                    features["has_nested_zip"] = True
                            except Exception:
                                pass
                            for name in names:
                                try:
                                    if not name.lower().endswith((".zip", ".pt", ".pth")):
                                        continue
                                    nested = zf.read(name)
                                    if len(nested) > 4 and nested[:2] == b'PK':
                                        with zipfile.ZipFile(io.BytesIO(nested)) as nz:
                                            nnames = nz.namelist()
                                            # If any inner name looks like a pickle, record weak signal only
                                            try:
                                                if any(n.endswith((".pkl", ".pickle")) for n in nnames):
                                                    features["has_pickle_name_only"] = True
                                                    features["container_type"] = "zip:nested"
                                            except Exception:
                                                pass
                                            # Prefer known names then any *.pkl/*.pickle
                                            preferred = [pf for pf in ("data.pkl", "pickle", "model.pkl") if pf in nnames]
                                            scan_list = preferred + [n for n in nnames if n.endswith((".pkl", ".pickle")) and n not in preferred]
                                            for pf in scan_list:
                                                try:
                                                    inner = nz.read(pf)
                                                except Exception:
                                                    continue
                                                # Try direct disassembly; on failure, scan for protocol magic offsets
                                                try:
                                                    disassembly = list(pickletools.genops(inner))
                                                except Exception:
                                                    best_inner = []
                                                    for magic2 in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                                                        s2 = 0
                                                        while True:
                                                            j = inner.find(magic2, s2)
                                                            if j == -1:
                                                                break
                                                            s2 = j + 1
                                                            try:
                                                                alt2 = list(pickletools.genops(inner[j:]))
                                                                if len(alt2) > len(best_inner):
                                                                    best_inner = alt2
                                                            except Exception:
                                                                continue
                                                    if best_inner:
                                                        disassembly = best_inner
                                                    else:
                                                        continue
                                                opcode_counts = Counter()
                                                suspicious_opcodes = set(self.config.suspicious_opcodes)
                                                total_opcodes = 0
                                                suspicious_opcode_count = 0
                                                for opcode, arg, pos in disassembly:
                                                    opcode_counts[opcode.name] += 1
                                                    total_opcodes += 1
                                                    if opcode.name in suspicious_opcodes:
                                                        suspicious_opcode_count += 1
                                                features["opcode_count"] = total_opcodes
                                                features["suspicious_opcode_count"] = suspicious_opcode_count
                                                features["suspicious_opcode_ratio"] = (
                                                    suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0
                                                )
                                                for opcode_name, count in opcode_counts.items():
                                                    features[f"opcode_{opcode_name}"] = count
                                                # Structural and string checks on nested inner pickle
                                                features["has_inner_pickle"] = True
                                                features["container_type"] = "zip:nested"
                                                try:
                                                    if b'__reduce__' in inner or b'__setstate__' in inner:
                                                        features["has_functions"] = True
                                                    if b'import' in inner or b'os.system' in inner or b'subprocess' in inner:
                                                        features["has_modules"] = True
                                                except Exception:
                                                    pass
                                                try:
                                                    suspicious_modules = self.config.suspicious_modules
                                                    features["has_suspicious_modules"] = any(m.encode() in inner for m in suspicious_modules)
                                                    suspicious_functions = self.config.suspicious_functions
                                                    features["has_suspicious_functions"] = any(fn.encode() in inner for fn in suspicious_functions)
                                                except Exception:
                                                    pass
                                                return features
                                except Exception:
                                    continue
            except Exception as zip_e:
                logger.debug(f"ZIP pickle fallback failed: {zip_e}")
            # Optional 7z support if py7zr is available
            try:
                if getattr(self.config, 'enable_7z_scanning', True) and len(data) > 2 and data[:2] == b'7z':
                    try:
                        import py7zr  # type: ignore
                    except Exception:
                        raise RuntimeError("py7zr not installed")
                    with py7zr.SevenZipFile(io.BytesIO(data), mode='r') as z:
                        names = z.getnames()
                        for name in names:
                            if not (name.endswith('.pkl') or name.endswith('.pickle')):
                                continue
                            try:
                                # Prefer in-memory read if available
                                try:
                                    files = z.read([name])
                                    blob = files.get(name)
                                    if hasattr(blob, 'read'):
                                        inner = blob.read()
                                    else:
                                        inner = bytes(blob) if not isinstance(blob, (bytes, bytearray)) else blob
                                except Exception:
                                    # Fallback to extract to temp directory
                                    import tempfile
                                    import os
                                    with tempfile.TemporaryDirectory() as tmpd:
                                        z.extract(targets=[name], path=tmpd)
                                        fpath = os.path.join(tmpd, name)
                                        with open(fpath, 'rb') as fh:
                                            inner = fh.read()

                                # Try direct disassembly; on failure, scan for protocol magic offsets
                                try:
                                    disassembly = list(pickletools.genops(inner))
                                except Exception:
                                    best_inner = []
                                    for magic2 in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                                        s2 = 0
                                        while True:
                                            j = inner.find(magic2, s2)
                                            if j == -1:
                                                break
                                            s2 = j + 1
                                            try:
                                                alt2 = list(pickletools.genops(inner[j:]))
                                                if len(alt2) > len(best_inner):
                                                    best_inner = alt2
                                            except Exception:
                                                continue
                                    if best_inner:
                                        disassembly = best_inner
                                    else:
                                        raise
                                opcode_counts = Counter()
                                suspicious_opcodes = set(self.config.suspicious_opcodes)
                                total_opcodes = 0
                                suspicious_opcode_count = 0
                                for opcode, arg, pos in disassembly:
                                    opcode_counts[opcode.name] += 1
                                    total_opcodes += 1
                                    if opcode.name in suspicious_opcodes:
                                        suspicious_opcode_count += 1
                                features["opcode_count"] = total_opcodes
                                features["suspicious_opcode_count"] = suspicious_opcode_count
                                features["suspicious_opcode_ratio"] = (
                                    suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0
                                )
                                for opcode_name, count in opcode_counts.items():
                                    features[f"opcode_{opcode_name}"] = count
                                features["has_inner_pickle"] = True
                                features["container_type"] = "7z"
                                return features
                            except Exception:
                                # Minimal nested inner pickle signal if disassembly failed
                                try:
                                    features["has_inner_pickle"] = True
                                    features["container_type"] = "zip:nested"
                                    if b'__reduce__' in inner or b'__setstate__' in inner:
                                        features["has_functions"] = True
                                    if b'import' in inner or b'os.system' in inner or b'subprocess' in inner:
                                        features["has_modules"] = True
                                    suspicious_modules = self.config.suspicious_modules
                                    features["has_suspicious_modules"] = any(m.encode() in inner for m in suspicious_modules)
                                    suspicious_functions = self.config.suspicious_functions
                                    features["has_suspicious_functions"] = any(fn.encode() in inner for fn in suspicious_functions)
                                except Exception:
                                    pass
                                return features
            except Exception as z7e:
                logger.debug(f"7z pickle fallback failed: {z7e}")

            # TAR / TAR.GZ support (joblib and packaging often use tarballs)
            try:
                import tarfile
                from io import BytesIO
                # Heuristic: tarfile.is_tarfile expects a file path; try stream open
                # We'll attempt to open regardless; tarfile will raise if not tar
                stream = BytesIO(data)
                try:
                    stream.seek(0)
                    if not getattr(self.config, 'enable_tar_scanning', True):
                        raise Exception('tar scanning disabled by config')
                    with tarfile.open(fileobj=stream, mode='r:*') as tf:
                        for member in tf.getmembers():
                            if not member.isfile():
                                continue
                            name = member.name
                            if not (name.endswith('.pkl') or name.endswith('.pickle')):
                                continue
                            try:
                                extracted = tf.extractfile(member)
                                if not extracted:
                                    continue
                                inner = extracted.read()
                                try:
                                    disassembly = list(pickletools.genops(inner))
                                except Exception:
                                    best_inner = []
                                    for magic2 in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                                        s2 = 0
                                        while True:
                                            j = inner.find(magic2, s2)
                                            if j == -1:
                                                break
                                            s2 = j + 1
                                            try:
                                                alt2 = list(pickletools.genops(inner[j:]))
                                                if len(alt2) > len(best_inner):
                                                    best_inner = alt2
                                            except Exception:
                                                continue
                                    if best_inner:
                                        disassembly = best_inner
                                    else:
                                        raise
                                opcode_counts = Counter()
                                suspicious_opcodes = set(self.config.suspicious_opcodes)
                                total_opcodes = 0
                                suspicious_opcode_count = 0
                                for opcode, arg, pos in disassembly:
                                    opcode_counts[opcode.name] += 1
                                    total_opcodes += 1
                                    if opcode.name in suspicious_opcodes:
                                        suspicious_opcode_count += 1
                                features["opcode_count"] = total_opcodes
                                features["suspicious_opcode_count"] = suspicious_opcode_count
                                features["suspicious_opcode_ratio"] = (
                                    suspicious_opcode_count / total_opcodes if total_opcodes > 0 else 0
                                )
                                for opcode_name, count in opcode_counts.items():
                                    features[f"opcode_{opcode_name}"] = count
                                features["has_inner_pickle"] = True
                                features["container_type"] = "tar"
                                return features
                            except Exception:
                                continue
                except Exception:
                    pass
            except Exception as tare:
                logger.debug(f"TAR pickle fallback failed: {tare}")

            # Default values if all parsing attempts fail
            features["opcode_count"] = 0
            features["suspicious_opcode_count"] = 0
            features["suspicious_opcode_ratio"] = 0

        return features

    def _extract_framework_signatures(self, data: bytes) -> Dict[str, Any]:
        features: Dict[str, Any] = {}
        lower = data.lower()
        is_torch = (b"torch" in lower) or (b"pytorch" in lower) or (b"pyTorch" in data)
        features["is_torch_artifact"] = bool(is_torch)
        has_torch_exec = any(s in lower for s in [b"os.system", b"subprocess", b"/bin/sh", b"bash -c"]) and is_torch
        features["has_suspicious_torch_strings"] = bool(has_torch_exec)
        return features

    def _extract_indirection_strings(self, data: bytes) -> Dict[str, Any]:
        """
        Detect common indirection patterns used to evade simple string/opcode checks,
        such as eval("__import__('os').system"), getattr(__import__('os'), 'system').
        """
        try:
            lower = data.lower()
        except Exception:
            lower = data

        # Unicode normalization and confusable mapping (basic): strip zero-width and map to ASCII skeleton
        norm_hits = 0
        try:
            import unicodedata
            import re
            text = data.decode('utf-8', errors='ignore')
            # Remove zero-width characters
            text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]", "", text)
            text_norm = unicodedata.normalize('NFKC', text).lower()
            # Confusable replacements (minimal set)
            conf_map = {
                '\u0455': 's',  # Cyrillic small letter dze/Es -> s
                '\u0131': 'i',  # dotless i
            }
            for k, v in conf_map.items():
                text_norm = text_norm.replace(k, v)
            # Remove non-letters to catch spaced tokens
            letters_only = re.sub(r"[^a-z]", "", text_norm)
            for tok in ("os", "system", "subprocess", "import", "getattr", "eval"):
                if tok in letters_only:
                    norm_hits += 1
        except Exception:
            pass

        indicators = {
            "has_eval_string": b"eval(" in lower,
            "has_dynamic_import_string": b"__import__(" in lower,
            "has_getattr_import_string": b"getattr(__import__(" in lower,
        }
        indicators["has_indirection_strings"] = any(indicators.values())
        indicators["normalized_token_hits"] = norm_hits
        indicators["has_normalized_suspicious_any"] = norm_hits > 0
        indicators["has_normalized_multiple_tokens"] = norm_hits >= 2
        return indicators

    def _extract_obfuscation_signatures(self, data: bytes) -> Dict[str, Any]:
        features: Dict[str, Any] = {}
        try:
            lower = data.lower()
        except Exception:
            lower = data

        # builtins.* indicators
        builtins_patterns = [
            b"builtins.eval",
            b"builtins.getattr",
            b"builtins.__import__",
            b"__builtins__",
        ]
        features["has_builtins_indicators"] = any(p in lower for p in builtins_patterns)

        # base64 encodings of suspicious tokens
        suspicious_tokens = [
            b"os", b"subprocess", b"system", b"popen", b"eval", b"__import__", b"getattr",
        ]
        import base64
        base64_hits = 0
        for tok in suspicious_tokens:
            try:
                b64 = base64.b64encode(tok)
            except Exception:
                continue
            if b64 in data or b64.lower() in data:
                base64_hits += 1
        features["base64_suspicious_hits"] = base64_hits
        features["has_base64_suspicious_any"] = base64_hits > 0
        # Strong if multiple tokens encoded
        features["has_base64_multiple_tokens"] = base64_hits >= 2
        
        # Normalized string heuristics: strip non-letters and collapse separators
        try:
            import re
            import unicodedata
            try:
                text = data.decode('utf-8', errors='ignore')
            except Exception:
                text = ''
            # Unicode normalization
            text_norm = unicodedata.normalize('NFKC', text).lower()
            # Strip non-letter characters to catch o.s.s y s t e m etc.
            letters_only = re.sub(r"[^a-z]", "", text_norm)
            suspicious_norm_tokens = [
                "os", "system", "subprocess", "popen", "eval", "import", "getattr"
            ]
            norm_hits = sum(1 for tok in suspicious_norm_tokens if tok in letters_only)
            features["normalized_token_hits"] = norm_hits
            features["has_normalized_suspicious_any"] = norm_hits > 0
            features["has_normalized_multiple_tokens"] = norm_hits >= 2
        except Exception:
            features["normalized_token_hits"] = 0
            features["has_normalized_suspicious_any"] = False
            features["has_normalized_multiple_tokens"] = False
        return features

    def _extract_evasion_indicators(self, data: bytes) -> Dict[str, Any]:
        features: Dict[str, Any] = {}
        lower = data.lower() if isinstance(data, (bytes, bytearray)) else b""
        # pip install patterns (CVE-2025-1716 style)
        features["has_pip_main_call"] = (b"pip.main(" in lower) or (b"pip._internal" in lower)
        features["has_pip_install_string"] = (b"pip install" in lower) or (b"-m pip install" in lower)
        # marshal-based payload hints
        features["has_marshal_usage"] = (b"marshal" in lower and (b"loads" in lower or b"load" in lower))
        # joblib artifacts
        features["is_joblib_artifact"] = (b"joblib" in lower) or (b"numpy.core.multiarray" in lower)
        # Broken pickle structure hints
        features["has_broken_pickle_hints"] = (b"PROTO" not in lower and b"FRAME" not in lower and b"STOP" not in lower and len(data) > 0)
        return features

    def _extract_structural_features(self, data: bytes) -> Dict[str, Any]:
        features = {"max_depth": 0, "object_count": 0, "has_modules": False, "has_functions": False}
        try:
            # This part would typically involve a more robust parser or AST analysis
            # For a mock, we can look for common indicators
            if b'__reduce__' in data or b'__setstate__' in data:
                features["has_functions"] = True
            if b'import' in data or b'os.system' in data or b'subprocess' in data:
                features["has_modules"] = True
            
            # Simple heuristic for max_depth and object_count
            # This is a very basic approximation and might not be accurate for complex pickles
            features["object_count"] = data.count(b'(') + data.count(b'[') + data.count(b'{')
            features["max_depth"] = max(0, data.count(b'(') - data.count(b')')) # Very rough estimate

        except Exception as e:
            logger.debug(f"Error extracting structural features: {e}")
        return features

    def _extract_byte_features(self, data: bytes) -> Dict[str, Any]:
        features = {}
        total_bytes = len(data)
        if total_bytes == 0:
            features["entropy"] = 0.0
            features["printable_ratio"] = 0.0
            features["null_byte_ratio"] = 0.0
            features["high_bit_ratio"] = 0.0
            features["byte_diversity"] = 0.0
            return features

        # Entropy
        import math
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total_bytes
            # Guard against log2(0) if any rounding issues
            if p > 0.0:
                entropy -= p * math.log2(p)
        features["entropy"] = entropy

        # Printable characters ratio
        printable_chars = sum(1 for byte in data if 32 <= byte <= 126)
        features["printable_ratio"] = printable_chars / total_bytes

        # Null byte ratio
        null_bytes = data.count(0)
        features["null_byte_ratio"] = null_bytes / total_bytes

        # High bit characters ratio (bytes > 127)
        high_bit_chars = sum(1 for byte in data if byte > 127)
        features["high_bit_ratio"] = high_bit_chars / total_bytes

        # Byte diversity
        features["byte_diversity"] = len(counts) / 256.0

        return features

    def _calculate_compression_ratio(self, data: bytes) -> float:
        import zlib
        if not data:
            return 0.0
        compressed_data = zlib.compress(data)
        return len(compressed_data) / len(data)

    def _check_suspicious_modules(self, data: bytes) -> bool:
        suspicious_modules = self.config.suspicious_modules
        for module in suspicious_modules:
            if module.encode() in data:
                return True
        return False

    def _check_suspicious_functions(self, data: bytes) -> bool:
        suspicious_functions = self.config.suspicious_functions
        for func in suspicious_functions:
            if func.encode() in data:
                return True
        return False


