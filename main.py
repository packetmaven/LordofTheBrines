
import argparse
import base64
import io
import json
import logging
import os
import sys

from config import Config
from detector import LordofTheBrines
from result import DetectionResult

logger = logging.getLogger("lordofthebrines.main")

def _print_png_banner_once() -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.box import SIMPLE
        from rich.image import Image
        console = Console()
        png_path = os.path.join(os.path.dirname(__file__), "LordoftheBrines.png")
        if os.path.exists(png_path):
            img = Image(png_path, width=console.size.width - 4)
            console.print(Panel(img, box=SIMPLE, border_style="grey37"))
    except Exception:
        # Silently skip if terminal or environment can't render images
        pass

def main():
    logging.basicConfig(level=logging.DEBUG) # Added this line
    parser = argparse.ArgumentParser(
        description="LordofTheBrines CLI for detecting malicious pickle files."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to the pickle file or directory to scan. Defaults to current directory.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Scan directories recursively.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output file for scan results (e.g., results.json).",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="text",
        choices=["text", "json", "html"],
        help="Output format (text, json, or html). Defaults to text.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output."
    )
    parser.add_argument(
        "--rich",
        action="store_true",
        help="Use Rich colored table output for text format.",
    )
    parser.add_argument(
        "--entropy-segments",
        type=int,
        default=None,
        help="Number of segments for entropy profiling (higher = more resolution).",
    )
    parser.add_argument(
        "--entropy-zscore",
        action="store_true",
        help="Overlay z-score spikes (>2σ) on entropy profile to highlight anomalies.",
    )
    
    # Advanced analysis options
    parser.add_argument(
        "-b", "--behavioral", "--enable-behavioral-analysis",
        action="store_true",
        help="Enable behavioral analysis in secure sandbox environment for maximum detection."
    )
    parser.add_argument(
        "-i", "--threat-intelligence", "--enable-threat-intelligence",
        action="store_true", 
        help="Enable threat intelligence integration for enhanced detection with external feeds."
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.8,
        metavar="[0.0-1.0]",
        help="Detection threshold (0.0-1.0). Lower values = more sensitive detection. Default: 0.8"
    )
    parser.add_argument(
        "--max-analysis",
        action="store_true",
        help="Enable all advanced analysis features (behavioral + threat intelligence + sensitive threshold)."
    )
    parser.add_argument(
        "--strict-torch",
        action="store_true",
        help="Be stricter with Torch/Tensor artifacts: if Torch signatures are present with few opcodes, bias toward malicious."
    )

    # Threat intel and validation toggles
    parser.add_argument(
        "--yara",
        action="store_true",
        help="Enable YARA scanning (uses bundled rules unless overridden)."
    )
    parser.add_argument(
        "--yara-rules",
        type=str,
        default=None,
        help="Path to YARA rules file (defaults to rules/pickle_rules.yar)."
    )
    parser.add_argument(
        "--yara-rules-url",
        type=str,
        default=None,
        help="URL to download YARA rules from (stored under ~/.lordofthebrines/rules)."
    )
    parser.add_argument(
        "--fickling",
        action="store_true",
        help="Enable Fickling allowlist validation for unsafe pickle ops."
    )

    # Confidence calibration and explanations
    parser.add_argument(
        "--no-calibration",
        action="store_true",
        help="Disable confidence calibration."
    )
    parser.add_argument(
        "--calibration-strategy",
        type=str,
        choices=["rule_based", "static"],
        default=None,
        help="Calibration strategy: rule_based or static (default from config)."
    )
    parser.add_argument(
        "--calibration-temperature",
        type=float,
        default=None,
        help="Temperature for static calibration (lower=sharper, higher=softer)."
    )
    parser.add_argument(
        "--max-explanations",
        type=int,
        default=None,
        help="Maximum number of top reasons to include in explanations."
    )

    # Drift monitoring (ADWIN)
    parser.add_argument(
        "--drift",
        action="store_true",
        help="Enable concept drift monitoring."
    )
    parser.add_argument(
        "--adwin",
        action="store_true",
        help="Enable ADWIN-based drift detection (if skmultiflow available)."
    )
    parser.add_argument(
        "--adwin-delta",
        type=float,
        default=None,
        help="ADWIN delta sensitivity (smaller=more sensitive)."
    )

    # Performance: caching and parallelism
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable in-memory feature cache."
    )
    parser.add_argument(
        "--feature-cache-size",
        type=int,
        default=None,
        help="Max entries in the feature cache."
    )
    parser.add_argument(
        "--no-parallel-archives",
        action="store_true",
        help="Disable parallel inner-archive scanning."
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Max parallel workers for archive scanning."
    )

    parser.add_argument(
        "--ir-profile",
        action="store_true",
        help="Incident response profile: auto-lower thresholds on high-signal indicators and print rule notes.",
    )
    parser.add_argument(
        "--ir-strict",
        action="store_true",
        help="Stricter IR preset: includes --ir-profile lowering plus quarantine/review tagging (optionally copies to --quarantine-dir).",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=str,
        default=None,
        help="When used with --ir-strict, copy quarantined files into this directory for triage.",
    )

    args = parser.parse_args()

    # Only show banner for text output; never for JSON to keep stdout machine-readable
    if args.format == "text":
        _print_png_banner_once()

    # Validate threshold range
    if not 0.0 <= args.threshold <= 1.0:
        logger.error("Detection threshold must be between 0.0 and 1.0")
        return 1

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Configure advanced analysis options
    config = Config()
    config.detection_threshold = args.threshold
    config.strict_torch = bool(args.strict_torch)
    # Threat intel
    if args.yara or args.max_analysis:
        config.enable_yara = True
    if args.yara_rules is not None:
        config.yara_rules_path = args.yara_rules
    if args.yara_rules_url is not None:
        try:
            from yara_detector import download_rules
            dl = download_rules(args.yara_rules_url)
            if dl:
                config.enable_yara = True
                config.yara_rules_path = dl
        except Exception as e:
            logger.warning(f"Failed to download yara rules: {e}")
    if args.fickling or args.max_analysis:
        config.enable_fickling_hook = True
    # Calibration/explanations
    if args.no_calibration:
        config.enable_confidence_calibration = False
    if args.calibration_strategy is not None:
        config.calibration_strategy = args.calibration_strategy
    if args.calibration_temperature is not None:
        config.calibration_temperature = float(args.calibration_temperature)
    if args.max_explanations is not None:
        config.max_explanations = int(args.max_explanations)
    # Drift
    if args.drift or args.max_analysis:
        config.enable_drift_monitor = True
    if args.adwin:
        config.enable_adwin_drift = True
    if args.adwin_delta is not None:
        config.adwin_delta = float(args.adwin_delta)
    # Performance
    if args.no_cache:
        config.enable_feature_cache = False
    if args.feature_cache_size is not None:
        config.feature_cache_size = int(args.feature_cache_size)
    if args.no_parallel_archives:
        config.enable_parallel_archive_scanning = False
    if args.max_workers is not None:
        config.max_parallel_workers = int(args.max_workers)
    
    if args.behavioral or args.max_analysis:
        config.enable_behavioral_analysis = True
        logger.info("Behavioral analysis enabled")
        
    if args.threat_intelligence or args.max_analysis:
        config.enable_threat_intelligence = True  
        logger.info("Threat intelligence integration enabled")
        
    if args.max_analysis:
        config.detection_threshold = 0.7  # More sensitive for max analysis
        logger.info("Maximum analysis mode enabled - using sensitive detection threshold (0.7)")

    logger.info(f"Detection threshold set to: {config.detection_threshold}")
    
    detector = LordofTheBrines(config)

    results = {}
    if os.path.isfile(args.path):
        result = detector.scan_file(args.path)
        results[args.path] = result
        # Track adaptive threshold note if requested
        if args.ir_profile or args.ir_strict:
            feats = getattr(result, 'features', {}) or {}
            notes: list[str] = []
            lowered = None
            # Start from 0.8 then lower
            thr = 0.8
            yh = feats.get("yara_hits") or []
            if isinstance(yh, list) and any("Pickle_RCE_Core_Strings" in h or "Pickle_Marshal_Obfuscation" in h for h in yh):
                thr = min(thr, 0.6); notes.append("IR: YARA core/gadget rule matched → threshold 0.6")
            if int(feats.get("fickling_hits", 0)) >= 2 and (feats.get("opcode_REDUCE", 0) > 0) and ((feats.get("opcode_GLOBAL", 0) > 0) or (feats.get("opcode_STACK_GLOBAL", 0) > 0)):
                thr = min(thr, 0.6); notes.append("IR: Fickling GLOBAL/REDUCE unsafe ops ≥2 → threshold 0.6")
            if feats.get("has_inner_pickle"):
                thr = min(thr, 0.6); notes.append("IR: inner pickle parsed → threshold 0.6")
            # 0.5 class
            ind = bool(feats.get("has_indirection_strings"))
            norm3 = int(feats.get("normalized_token_hits", 0)) >= 3
            marshal = bool(feats.get("has_marshal_usage"))
            susratio = float(feats.get("suspicious_opcode_ratio", 0.0))
            tuple_reduce = (feats.get("opcode_REDUCE", 0) > 0) and ((feats.get("opcode_TUPLE1", 0) + feats.get("opcode_TUPLE2", 0) + feats.get("opcode_TUPLE3", 0)) > 0)
            b64z = any(k in (feats.get("yara_hits") or []) for k in ["Pickle_Marshal_Obfuscation","Pickle_Base64_Exec_Combinator"]) if isinstance(feats.get("yara_hits"), list) else False
            conds = sum([ind, norm3, (marshal and b64z), (susratio >= 0.12 and tuple_reduce)])
            if conds >= 2:
                thr = min(thr, 0.5); notes.append("IR: multiple high-signal indicators (>=2) → threshold 0.5")
            lowered = thr
            # Attach note into result for output layers
            result.features["ir_profile_threshold"] = lowered
            result.features["ir_profile_notes"] = notes
            # Strict mode: quarantine/review tagging and optional copy
            if args.ir_strict:
                strict_notes: list[str] = []
                quarantine_threshold = min(lowered, 0.5)
                strong = (
                    (isinstance(yh, list) and any("Pickle_RCE_Core_Strings" in h or "Pickle_Marshal_Obfuscation" in h for h in yh))
                    or (int(feats.get("fickling_hits", 0)) >= 2 and (feats.get("opcode_REDUCE", 0) > 0) and ((feats.get("opcode_GLOBAL", 0) > 0) or (feats.get("opcode_STACK_GLOBAL", 0) > 0)))
                    or bool(feats.get("has_inner_pickle"))
                )
                to_quarantine = (result.confidence >= quarantine_threshold) or strong
                review_bucket = (result.confidence >= 0.45 and result.confidence < quarantine_threshold and (conds >= 1))
                result.features["ir_strict_quarantine"] = bool(to_quarantine)
                result.features["ir_strict_review"] = bool(review_bucket)
                if to_quarantine and args.quarantine_dir:
                    try:
                        import shutil, os
                        os.makedirs(args.quarantine_dir, exist_ok=True)
                        dest = os.path.join(args.quarantine_dir, os.path.basename(args.path if os.path.isfile(args.path) else path))
                        shutil.copy2(args.path if os.path.isfile(args.path) else path, dest)
                        strict_notes.append(f"copied to {dest}")
                    except Exception:
                        strict_notes.append("copy failed")
                if to_quarantine:
                    strict_notes.append(f"IR strict: quarantine (conf {result.confidence:.2f} ≥ {quarantine_threshold:.2f} or strong indicator)")
                elif review_bucket:
                    strict_notes.append("IR strict: review bucket (0.45 ≤ conf < quarantine threshold with indicators)")
                result.features["ir_strict_notes"] = strict_notes
    elif os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for file in files:
                if file.endswith(".pkl"):
                    file_path = os.path.join(root, file)
                    result = detector.scan_file(file_path)
                    results[file_path] = result
            if not args.recursive:
                break
    else:
        logger.error(f"Invalid path: {args.path}")
        return 1

    malicious_files = {
        path: result
        for path, result in results.items()
        if result.is_malicious
    }

    if args.output:
        if args.format == "json":
            with open(args.output, "w") as f:
                json_results = {
                    path: result.to_dict() for path, result in results.items()
                }
                json.dump(json_results, f, indent=2)
        elif args.format == "html":
            out_path = args.output or "report.html"
            _write_html_report(out_path, results, entropy_segments=args.entropy_segments, entropy_zscore=args.entropy_zscore)
            print(f"Wrote HTML report to {out_path}")
        else:
            with open(args.output, "w") as f:
                for path, result in results.items():
                    f.write(f"File: {path}\n")
                    f.write(f"  Is Malicious: {result.is_malicious}\n")
                    f.write(f"  Confidence: {result.confidence:.2f}\n")
                    if result.explanation:
                        f.write(f"  Explanation: {result.explanation}\n")
                    if result.threat_type:
                        f.write(f"  Threat Type: {result.threat_type}\n")
                    if result.feature_importances:
                        f.write(f"  Feature Importances: {result.feature_importances}\n")
                    f.write("\n")
    else:
        if args.format == "json":
            json_results = {
                path: result.to_dict() for path, result in results.items()
            }
            print(json.dumps(json_results, indent=2))
        elif args.format == "html":
            out_path = args.output or "report.html"
            _write_html_report(out_path, results, entropy_segments=args.entropy_segments, entropy_zscore=args.entropy_zscore)
            print(f"Wrote HTML report to {out_path}")
        else:
            if args.rich:
                _print_rich_summary(results)
            else:
                print(f"Scanned {len(results)} files, found {len(malicious_files)} malicious\n")
                if malicious_files:
                    print("Malicious files:")
                    for path, result in malicious_files.items():
                        print(f"- {path} (Confidence: {result.confidence:.2f})")

    return 0

if __name__ == "__main__":
    sys.exit(main())

def _print_rich_summary(results: dict) -> None:
    try:
        from rich.table import Table
        from rich.console import Console
        from rich.text import Text
    except Exception:
        print("Rich is not available; falling back to plain text.")
        total = len(results)
        mal = sum(1 for r in results.values() if r.is_malicious)
        print(f"Scanned {total} files, found {mal} malicious")
        return
    table = Table(title="LordofTheBrines Scan Summary", show_lines=False)
    table.add_column("File", overflow="fold")
    table.add_column("Verdict")
    table.add_column("Confidence")
    table.add_column("Top Reason")
    table.add_column("YARA/Fickling")
    for path, res in results.items():
        verdict = "Malicious" if res.is_malicious else "Benign"
        verdict_text = Text(verdict, style=("bold red" if res.is_malicious else "bold green"))
        reasons = (res.explanation or "").split("; ")
        top_reason = reasons[0] if reasons else ""
        feats = getattr(res, 'features', {}) or {}
        yh = feats.get("yara_hit_count") or feats.get("yara_hits") or 0
        if isinstance(yh, list):
            yh = len(yh)
        fk = feats.get("fickling_hits", 0)
        yf = f"Y:{yh} F:{fk}"
        table.add_row(path, verdict_text, f"{res.confidence:.2f}", top_reason, yf)
    Console().print(table)


def _write_html_report(out_path: str, results: dict, *, entropy_segments: int | None = None, entropy_zscore: bool = False) -> None:
    html_parts = [
        "<html><head><meta charset='utf-8'><title>LordofTheBrines Report</title>",
        "<style>body{font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;padding:16px;} .brand{display:flex;justify-content:center;margin-bottom:12px;} .card{border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:16px;} .badge{display:inline-block;padding:2px 8px;border-radius:12px;background:#eee;margin-right:6px;} .mal{color:#b00020;font-weight:600;} .ben{color:#1b5e20;font-weight:600;} .chip{display:inline-block;background:#f1f3f4;border-radius:12px;padding:4px 8px;margin:2px;} h2{margin:8px 0;} h3{margin:10px 0 6px;} img{max-width:100%;height:auto;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #eee;padding:6px;text-align:left;} th{background:#fafafa;} .row{display:flex;gap:12px;flex-wrap:wrap;} .col{flex:1 1 340px;min-width:280px;} .gauge{width:240px;margin:6px 0;}</style>",
        "</head><body>",
    ]
    # Embed brand image (same PNG used in README) at top of report
    try:
        png_path = os.path.join(os.path.dirname(__file__), "LordoftheBrines.png")
        with open(png_path, 'rb') as pf:
            b64 = base64.b64encode(pf.read()).decode('ascii')
        html_parts.append(f"<div class='brand'><img src='data:image/png;base64,{b64}' alt='LordofTheBrines' /></div>")
    except Exception:
        html_parts.append("<h1>LordofTheBrines Scan Report</h1>")
    for path, res in results.items():
        feats = getattr(res, 'features', {}) or {}
        verdict = "Malicious" if res.is_malicious else "Benign"
        vclass = "mal" if res.is_malicious else "ben"
        reasons = (res.explanation or "").split("; ")
        # Badges
        yrules = feats.get("yara_hits") or feats.get("yara_matched_rules") or []
        if isinstance(yrules, int):
            ycount = yrules
            yrules = []
        else:
            ycount = len(yrules)
        fhits = int(feats.get("fickling_hits", 0))
        torch_badge = "<span class='badge'>Torch</span>" if feats.get("is_torch_artifact") else ""
        joblib_badge = "<span class='badge'>Joblib</span>" if feats.get("is_joblib_artifact") else ""
        badges = f"<span class='badge'>YARA:{ycount}</span><span class='badge'>Fickling:{fhits}</span>{torch_badge}{joblib_badge}"
        html_parts.append(f"<div class='card'><h2>{path}</h2><div><span class='{vclass}'>{verdict}</span> &middot; Confidence {res.confidence:.2f} {badges}</div>")
        # Risk gauge
        risk = res.confidence if res.is_malicious else (1.0 - res.confidence)
        gimg = _plot_gauge_base64(risk)
        if gimg:
            html_parts.append(f"<img class='gauge' src='data:image/png;base64,{gimg}' alt='risk gauge' />")
        if reasons and reasons[0]:
            chips = "".join([f"<span class='chip'>{r}</span>" for r in reasons[:5]])
            html_parts.append(f"<div style='margin-top:6px'>{chips}</div>")
            # Context keys for the top three explanations
            kitems = _explanation_key_items(reasons[:3], feats)
            if kitems:
                html_parts.append("<div class='row'>")
                for title, desc in kitems:
                    html_parts.append(f"<div class='col'><div class='card'><strong>{title}</strong><br/><div style='font-size:0.95em;line-height:1.35'>{desc}</div></div></div>")
                html_parts.append("</div>")
        # Row of visuals (clean top row: opcodes | feature contributions | entropy)
        html_parts.append("<div class='row'>")
        op_img_b64 = _plot_opcodes_base64(feats)
        if op_img_b64:
            html_parts.append("<div class='col'><h3>Opcode distribution</h3>")
            html_parts.append(f"<img src='data:image/png;base64,{op_img_b64}' /></div>")
        imp_img = _plot_importances_base64(getattr(res, 'feature_importances', {}) or {})
        if imp_img:
            html_parts.append("<div class='col'><h3>Feature contributions</h3>")
            html_parts.append(f"<img src='data:image/png;base64,{imp_img}' /></div>")
        ent_img_b64 = _plot_entropy_profile_base64(path, segments=entropy_segments, zscore=entropy_zscore)
        if ent_img_b64:
            html_parts.append("<div class='col'><h3>Entropy profile</h3>")
            html_parts.append(f"<img src='data:image/png;base64,{ent_img_b64}' /></div>")
        html_parts.append("</div>")
        # Second row: full-width heatmap for readability
        heat_img = _plot_opcode_heatmap_base64(path)
        if heat_img:
            html_parts.append("<div class='row'><div class='col' style='flex:1 1 100%'><h3>Opcode sequence (bigram) heatmap</h3>")
            html_parts.append(f"<img src='data:image/png;base64,{heat_img}' /></div></div>")
        # String/obfuscation panel and container info
        subset_keys = [
            "has_indirection_strings","has_builtins_indicators","base64_suspicious_hits","has_marshal_usage","has_pip_install_string","has_pip_main_call","normalized_token_hits","has_inner_pickle","container_type",
        ]
        rows = "".join([f"<tr><th>{k}</th><td>{feats.get(k,'')}</td></tr>" for k in subset_keys if k in feats])
        if rows:
            html_parts.append("<h3>Indicators & container</h3>")
            html_parts.append(f"<table>{rows}</table>")
        # Container tree (best-effort)
        tree = _container_tree_html(path)
        if tree:
            html_parts.append("<h3>Container tree</h3>")
            html_parts.append(tree)
        html_parts.append("</div>")
    html_parts.append("</body></html>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))


def _plot_opcodes_base64(features: dict) -> str | None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        # Collect opcode counts
        items = [(k[7:], v) for k, v in features.items() if isinstance(v, (int, float)) and k.startswith('opcode_') and v > 0]
        if not items:
            return None
        items.sort(key=lambda x: x[1], reverse=True)
        labels = [k for k, _ in items[:20]]
        values = [v for _, v in items[:20]]
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.bar(labels, values, color='#546E7A')
        ax.set_ylabel('count')
        ax.set_title('Top opcodes')
        ax.tick_params(axis='x', rotation=45, labelsize=8)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=160)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def _plot_entropy_profile_base64(path: str, *, segments: int | None = None, zscore: bool = False) -> str | None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import math
        with open(path, 'rb') as fh:
            data = fh.read()
        if not data:
            return None
        # Choose number of segments to guarantee >= 2 points, even for tiny files
        num_segments = segments if (isinstance(segments, int) and segments > 1) else min(64, max(2, len(data)//64))
        seg_sz = max(1, (len(data) + num_segments - 1)//num_segments)
        xs, ys = [], []
        from collections import Counter
        for i in range(0, len(data), seg_sz):
            chunk = data[i:i+seg_sz]
            c = Counter(chunk)
            total = max(1, len(chunk))
            ent = 0.0
            for n in c.values():
                p = n/total
                if p > 0:
                    ent -= p * math.log2(p)
            xs.append(i)
            ys.append(ent)
        if len(xs) < 2:
            # Duplicate last point to make a visible line
            xs.append(xs[-1] + max(1, seg_sz))
            ys.append(ys[-1])
        fig, ax = plt.subplots(figsize=(6,2.2))
        ax.plot(xs, ys, color='#1E88E5', marker='o', markersize=2)
        if zscore and len(ys) >= 4:
            import numpy as np
            mu = float(np.mean(ys))
            sd = float(np.std(ys) or 1.0)
            zs = [(y - mu)/sd for y in ys]
            spikes = [(x, y) for x, y, z in zip(xs, ys, zs) if abs(z) >= 2.0]
            if spikes:
                ax.scatter([x for x, _ in spikes], [y for _, y in spikes], color='#D81B60', s=16, label='z>=2σ')
                ax.legend(loc='best', fontsize=8)
        ax.set_xlabel('offset (bytes)')
        ax.set_ylabel('entropy (bits)')
        ax.set_title('Entropy over file')
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=160)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def _plot_importances_base64(importances: dict) -> str | None:
    try:
        if not importances:
            return None
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        items = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:12]
        labels = [k for k, _ in items]
        values = [v for _, v in items]
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.barh(labels, values, color='#8E24AA')
        ax.invert_yaxis()
        ax.set_xlabel('weight')
        ax.set_title('Top feature contributions')
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=160)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def _plot_gauge_base64(score: float) -> str | None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        fig, ax = plt.subplots(figsize=(3, 1.6), subplot_kw={'projection': None})
        ax.axis('off')
        # Draw background bar
        ax.barh([0], [1.0], color='#eee', height=0.3)
        # Draw score
        color = '#b00020' if score >= 0.6 else ('#F9A825' if score >= 0.3 else '#1b5e20')
        ax.barh([0], [max(0.01, min(1.0, score))], color=color, height=0.3)
        ax.set_xlim(0, 1)
        ax.set_ylim(-1, 1)
        ax.text(0.5, 0.5, f"Risk {score*100:.0f}%", ha='center', va='center', fontsize=10)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=160)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def _opcode_sequence_from_file(path: str) -> list[str]:
    try:
        import pickletools, zipfile, tarfile, io
        with open(path, 'rb') as fh:
            data = fh.read()
        seq: list[str] = []
        def disassemble_bytes(buf: bytes) -> list[str]:
            out: list[str] = []
            try:
                for op, arg, pos in pickletools.genops(buf):
                    nm = op.name
                    if nm.startswith('TUPLE'):
                        nm = 'TUPLE'
                    out.append(nm)
                return out
            except Exception:
                best: list[str] = []
                for magic in (b"\x80\x05", b"\x80\x04", b"\x80\x03", b"\x80\x02", b"\x80\x01", b"\x80\x00"):
                    s = 0
                    while True:
                        j = buf.find(magic, s)
                        if j == -1:
                            break
                        s = j + 1
                        try:
                            tmp: list[str] = []
                            for op, arg, pos in pickletools.genops(buf[j:]):
                                nm = op.name
                                if nm.startswith('TUPLE'):
                                    nm = 'TUPLE'
                                tmp.append(nm)
                            if len(tmp) > len(best):
                                best = tmp
                        except Exception:
                            continue
                return best

        # 1) Try direct (raw pickle)
        seq = disassemble_bytes(data)
        if seq:
            return seq[:400]
        # 2) ZIP containers
        try:
            if data[:2] == b'PK':
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    # Prefer common pickle names first
                    names = zf.namelist()
                    preferred = [n for n in ("data.pkl","model.pkl","pickle") if n in names]
                    candidates = preferred + [n for n in names if n.endswith(('.pkl','.pickle'))]
                    for n in candidates:
                        try:
                            inner = zf.read(n)
                            seq = disassemble_bytes(inner)
                            if seq:
                                return seq[:400]
                        except Exception:
                            continue
        except Exception:
            pass
        # 3) TAR/TGZ containers
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    if not (m.name.endswith('.pkl') or m.name.endswith('.pickle')):
                        continue
                    try:
                        f = tf.extractfile(m)
                        if not f:
                            continue
                        inner = f.read()
                        seq = disassemble_bytes(inner)
                        if seq:
                            return seq[:400]
                    except Exception:
                        continue
        except Exception:
            pass
        return seq[:400]
    except Exception:
        return []


def _plot_opcode_heatmap_base64(path: str) -> str | None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        from collections import Counter
        seq = _opcode_sequence_from_file(path)
        if not seq or len(seq) < 2:
            return None
        # First try focused tokens
        focus = ['GLOBAL', 'STACK_GLOBAL', 'TUPLE', 'REDUCE']
        focus_idx = {t: i for i, t in enumerate(focus)}
        focus_mat = np.zeros((len(focus), len(focus)), dtype=float)
        for a, b in zip(seq, seq[1:]):
            if a in focus_idx and b in focus_idx:
                focus_mat[focus_idx[a], focus_idx[b]] += 1
        use_focus = focus_mat.sum() > 0
        if use_focus:
            tokens = focus
            mat = focus_mat
        else:
            # Build bigram over top-k opcodes observed
            counts = Counter(seq)
            tokens = [t for t, _ in counts.most_common(6)]
            idx = {t: i for i, t in enumerate(tokens)}
            mat = np.zeros((len(tokens), len(tokens)), dtype=float)
            for a, b in zip(seq, seq[1:]):
                if a in idx and b in idx:
                    mat[idx[a], idx[b]] += 1
            if mat.sum() == 0:
                return None
        fig, ax = plt.subplots(figsize=(6, 4))
        im = ax.imshow(mat, cmap='YlOrRd', interpolation='nearest')
        ax.set_xticks(range(len(tokens)))
        ax.set_yticks(range(len(tokens)))
        ax.set_xticklabels(tokens, rotation=45, ha='right')
        ax.set_yticklabels(tokens)
        ax.set_title('Opcode bigram heatmap')
        cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.ax.set_ylabel('count', rotation=90)
        # Annotate non-zero cells
        for i in range(len(tokens)):
            for j in range(len(tokens)):
                v = mat[i, j]
                if v > 0:
                    ax.text(j, i, int(v), ha='center', va='center', color='black', fontsize=8)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=160)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode('ascii')
    except Exception:
        return None


def _container_tree_html(path: str) -> str:
    try:
        import zipfile, tarfile
        html = []
        with open(path, 'rb') as fh:
            head = fh.read(8)
        # ZIP
        if head[:2] == b'PK':
            with zipfile.ZipFile(path, 'r') as zf:
                html.append("<ul>")
                for n in zf.namelist():
                    safe = n.replace('<','&lt;').replace('>','&gt;')
                    html.append(f"<li>{safe}</li>")
                html.append("</ul>")
        # TAR/TGZ
        elif head[:2] == b"\x1f\x8b" or True:
            try:
                with tarfile.open(path, 'r:*') as tf:
                    html.append("<ul>")
                    for m in tf.getmembers()[:50]:
                        safe = m.name.replace('<','&lt;').replace('>','&gt;')
                        html.append(f"<li>{safe}</li>")
                    html.append("</ul>")
            except Exception:
                pass
        return "".join(html)
    except Exception:
        return ""


def _explanation_key_items(reasons: list[str], features: dict) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    # Mapping of substrings to explanations
    mapping: list[tuple[str, str, str]] = [
        (
            "Opcode chain",
            "Opcode chain: GLOBAL/STACK_GLOBAL + REDUCE",
            "Pickle bytecode sequence that loads a global callable (GLOBAL/STACK_GLOBAL), often packs args with TUPLE, then invokes it via REDUCE. Attackers abuse this to call dangerous functions (e.g., os.system). A strong RCE indicator.",
        ),
        (
            "Indirection/obfuscation strings",
            "Import indirection/eval strings present",
            "Suspicious strings like eval(, __import__(, getattr(__import__(...), ...), builtins.eval/exec enabling dynamic import/execution. Frequently used to evade simple detectors.",
        ),
        (
            "normalized",
            "Normalized (homoglyph/ZW) suspicious tokens",
            "Tokens only visible after Unicode normalization and zero‑width removal (e.g., ‘ѕystem’ with Cyrillic ‘ѕ’, or ‘sys\u200btem’). We normalize (NFKC) and strip zero‑width to reveal hidden keywords like os/system/subprocess.",
        ),
        (
            "pip",
            "Pip installation strings",
            "The pickle content references pip installation calls (e.g., ‘pip install’, ‘pip.main’), which are unusual during deserialization and may pull remote code.",
        ),
        (
            "marshal",
            "marshal.loads usage",
            "The payload uses marshal.loads, often paired with base64/XOR to hide bytecode for execution.",
        ),
        (
            "YARA",
            "YARA rule match",
            "Signatures from YARA rules matched known malicious patterns (e.g., base64+exec, torch/joblib gadget hints).",
        ),
        (
            "Embedded inner pickle",
            "Embedded inner pickle in container",
            "An inner pickle was parsed from an archive or prefixed data. Attackers often nest payloads to bypass naive scanners.",
        ),
    ]
    used = set()
    def _yara_desc_from_features(feat: dict) -> str:
        try:
            hits = feat.get("yara_hits") or feat.get("yara_matched_rules") or []
            if isinstance(hits, list) and hits:
                safe = [str(h).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;') for h in hits]
                if len(safe) <= 6:
                    return "Matched YARA rules: " + ", ".join(safe)
                return "Matched YARA rules (top 6): " + ", ".join(safe[:6]) + f" (+{len(safe)-6} more)"
            count = feat.get("yara_hit_count")
            if isinstance(count, int) and count > 0:
                return f"YARA matched {count} rule(s)."
        except Exception:
            pass
        return "One or more YARA signatures matched known malicious strings or gadget patterns."

    for r in reasons:
        for key, title, desc in mapping:
            if key.lower() in r.lower() and title not in used:
                if title == "YARA rule match":
                    desc = _yara_desc_from_features(features)
                items.append((title, desc))
                used.add(title)
                break
    # If YARA/Fickling hits present but not covered by strings above, append contextual boxes
    try:
        hits = features.get("yara_hits") or features.get("yara_matched_rules") or []
        hit_count = features.get("yara_hit_count")
        has_hits = (isinstance(hits, list) and len(hits) > 0) or (isinstance(hit_count, int) and hit_count > 0)
        if has_hits and "YARA rule match" not in used:
            items.append(("YARA rule match", _yara_desc_from_features(features)))
    except Exception:
        pass
    try:
        fk = int(features.get("fickling_hits", 0))
        if fk:
            items.append(("Fickling unsafe pickle ops", "Fickling analysis flagged unsafe GLOBAL/REDUCE/BUILD operations that can execute code during unpickling."))
    except Exception:
        pass
    return items


