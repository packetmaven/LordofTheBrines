import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def validate_bytes(data: bytes) -> Dict[str, Any]:
    """
    Optional Fickling validation integration. If `fickling` is unavailable,
    return a neutral result. When available, run allowlist validation and
    return violations and a score.
    """
    try:
        import fickling  # type: ignore
        from fickling.analysis.bytecode import Bytecode
        from fickling.pickle.reader import PickleReader
        # Parse with Fickling
        reader = PickleReader(data)
        bytecode = Bytecode(reader)
        # Allowlist and unsafe ops detection
        unsafe: List[str] = []
        allowed_globals: List[str] = []
        try:
            from config import Config  # late import to avoid cycles
            cfg = Config()
            allowed_globals = getattr(cfg, 'fickling_allow_globals', []) or []
        except Exception:
            pass
        for op in bytecode:
            try:
                name = getattr(op, 'name', '')
            except Exception:
                name = ''
            if name in ("GLOBAL", "STACK_GLOBAL"):
                # Fickling can expose argument with module.attr; attempt extraction
                try:
                    target = getattr(op, 'arg', None)
                    if target is not None:
                        tgt = str(target)
                        if not any(tgt.startswith(g) for g in allowed_globals):
                            unsafe.append(f"GLOBAL:{tgt}")
                except Exception:
                    unsafe.append("GLOBAL")
            elif name in ("REDUCE", "BUILD", "INST", "NEWOBJ"):
                unsafe.append(name)
        # Also run a lightweight pickletools fallback and merge, to improve coverage
        try:
            import pickletools
            for op, arg, pos in pickletools.genops(data):
                nm = op.name
                if nm in ("GLOBAL", "STACK_GLOBAL"):
                    # pickletools doesn't give module.attr easily; just record name
                    unsafe.append(f"GLOBAL:{nm}")
                elif nm in ("REDUCE", "BUILD", "INST", "NEWOBJ"):
                    unsafe.append(nm)
        except Exception:
            pass
        # De-duplicate
        unsafe = list(dict.fromkeys(unsafe))
        score = min(1.0, len(unsafe) / 5.0)
        return {"fickling_unsafe_ops": unsafe, "fickling_score": score, "fickling_hits": len(unsafe)}
    except Exception as e:
        logger.debug(f"Fickling unavailable or failed: {e}")
        # Fallback: scan with pickletools for known unsafe ops
        try:
            import pickletools
            unsafe: List[str] = []
            for op, arg, pos in pickletools.genops(data):
                nm = op.name
                if nm in ("GLOBAL", "STACK_GLOBAL"):
                    unsafe.append(f"GLOBAL:{nm}")
                elif nm in ("REDUCE", "BUILD", "INST", "NEWOBJ"):
                    unsafe.append(nm)
            unsafe = list(dict.fromkeys(unsafe))
            score = min(1.0, len(unsafe) / 5.0)
            return {"fickling_unsafe_ops": unsafe, "fickling_score": score, "fickling_hits": len(unsafe)}
        except Exception:
            return {"fickling_unsafe_ops": [], "fickling_score": 0.0, "fickling_hits": 0}


