import os
import io
import json
import sys
import subprocess
import zipfile
import tarfile
import gzip
import pickle as pkl


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def gen_samples(base: str) -> None:
    ensure_dir(base)

    class EvalImport:
        def __reduce__(self):
            return (eval, ("__import__('os').system",))
    open(os.path.join(base, 'eval_import.pkl'), 'wb').write(pkl.dumps(EvalImport()))

    open(os.path.join(base, 'benign_large.pkl'), 'wb').write(
        pkl.dumps({'k': [list(range(50)), {'a': 'b'*50}]})
    )

    class InnerExploit:
        def __reduce__(self):
            import os
            return (os.system, ("echo NESTED",))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('data.pkl', pkl.dumps(InnerExploit()))
    open(os.path.join(base, 'nested_container.zip'), 'wb').write(buf.getvalue())

    # tar.gz with inner
    inner = pkl.dumps(InnerExploit())
    tarb = io.BytesIO()
    with tarfile.open(fileobj=tarb, mode='w') as tf:
        info = tarfile.TarInfo('inner.pkl')
        info.size = len(inner)
        tf.addfile(info, io.BytesIO(inner))
    with gzip.open(os.path.join(base, 'payload.tar.gz'), 'wb') as gz:
        gz.write(tarb.getvalue())

    # prefixed pklx
    with open(os.path.join(base, 'prefixed_code.pklx'), 'wb') as f:
        f.write(b"# header\n")
        class Payload:
            def __reduce__(self):
                import os
                return (os.system, ("echo PREF",))
        f.write(pkl.dumps(Payload()))

    # joblib hint benign
    open(os.path.join(base, 'joblib_hint.pkl'), 'wb').write(pkl.dumps({'fmt': 'joblib', 'array': 'numpy.core.multiarray'}))

    # Zero-width obfuscation around import/system
    class ZWObf:
        def __reduce__(self):
            # eval("__im\u200bport__('os').sys\u200btem('echo ZW')") pattern
            s = "__im\u200bport__('os').sys\u200btem('echo ZW')"
            return (eval, (s,))
    open(os.path.join(base, 'zero_width_obf.pkl'), 'wb').write(pkl.dumps(ZWObf()))

    # Homoglyph obfuscation (Cyrillic 'ѕ' in 'system')
    class HomoObf:
        def __reduce__(self):
            s = "__import__('os').ѕystem('echo HG')"  # U+0455 for 'ѕ'
            return (eval, (s,))
    open(os.path.join(base, 'homoglyph_obf.pkl'), 'wb').write(pkl.dumps(HomoObf()))

    # Base64 + marshal combo (static pattern)
    class B64Marshal:
        def __reduce__(self):
            code = "__import__('marshal').loads(__import__('base64').b64decode('AAAA'))"
            return (eval, (code,))
    open(os.path.join(base, 'b64_marshal_exec.pkl'), 'wb').write(pkl.dumps(B64Marshal()))

    # XOR+marshal hint (heuristic trigger)
    class XORMarshal:
        def __reduce__(self):
            blob = 'QUJDREVGR0hJSktMTU4='  # base64-like
            code = "__import__('marshal').loads('xor:'+__import__('base64').b64decode('" + blob + "').hex())"
            return (eval, (code,))
    open(os.path.join(base, 'xor_marshal_hint.pkl'), 'wb').write(pkl.dumps(XORMarshal()))

    # ZIP with suspicious names and malicious inner pickle
    class InnerBad:
        def __reduce__(self):
            import os
            return (os.system, ("echo ZIPBAD",))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('../e\u200bvil.pkl', b'not a pickle')
        zf.writestr('data.pkl', pkl.dumps(InnerBad()))
    open(os.path.join(base, 'zip_unicode_names.zip'), 'wb').write(zbuf.getvalue())

    # TAR.GZ with unicode long name
    inner = pkl.dumps(InnerBad())
    tarb = io.BytesIO()
    with tarfile.open(fileobj=tarb, mode='w') as tf:
        info = tarfile.TarInfo('𝓵𝓸𝓷𝓰_inner.pkl')
        info.size = len(inner)
        tf.addfile(info, io.BytesIO(inner))
    with gzip.open(os.path.join(base, 'unicode_payload.tar.gz'), 'wb') as gz:
        gz.write(tarb.getvalue())


def scan_json(path: str) -> dict:
    rc, out, err = run([sys.executable, 'LordofTheBrines_cli.py', path, '--max-analysis', '--format', 'json'])
    if rc != 0:
        print('Scan failed rc=', rc, 'stderr=', err)
        raise SystemExit(1)
    try:
        obj = json.loads(out)
        # Unwrap single-file mapping { "<path>": { ... } }
        if isinstance(obj, dict) and 'is_malicious' not in obj and len(obj) == 1:
            return next(iter(obj.values()))
        return obj
    except Exception:
        print('Invalid JSON for', path, 'out=', out, 'err=', err)
        raise SystemExit(1)


def main():
    base = '/tmp/lob_ci'
    gen_samples(base)

    cases = {
        'eval_import.pkl': True,
        'nested_container.zip': True,
        'payload.tar.gz': True,
        'prefixed_code.pklx': True,
        'benign_large.pkl': False,
        'joblib_hint.pkl': False,
        'zero_width_obf.pkl': True,
        'homoglyph_obf.pkl': True,
        'b64_marshal_exec.pkl': True,
        'xor_marshal_hint.pkl': True,
        'zip_unicode_names.zip': True,
        'unicode_payload.tar.gz': True,
    }

    failures = []
    for name, expect_mal in cases.items():
        res = scan_json(os.path.join(base, name))
        is_mal = bool(res.get('is_malicious'))
        if is_mal != expect_mal:
            failures.append((name, is_mal, res))

    if failures:
        print('CI scan failures:', len(failures))
        for name, is_mal, res in failures:
            print('Case:', name, 'is_malicious:', is_mal)
            print(json.dumps(res, indent=2))
        raise SystemExit(1)
    print('CI scan OK')


if __name__ == '__main__':
    main()


