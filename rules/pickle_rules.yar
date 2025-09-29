// LordofTheBrines YARA rules for malicious pickle indicators
// These rules focus on high-signal strings commonly embedded in malicious pickles.
// They are conservative and modular so matches are interpretable in reports.

rule Pickle_RCE_Core_Strings {
    meta:
        description = "Core RCE-enabling strings: dynamic import and eval/exec"
        author = "LordofTheBrines"
        reference = "https://docs.python.org/3/library/pickle.html#security"
    strings:
        $i1 = "__import__(" nocase ascii
        $i2 = "getattr(__import__(" nocase ascii
        $e1 = "eval(" nocase ascii
        $e2 = "exec(" nocase ascii
        $b1 = "builtins.eval" nocase ascii
        $b2 = "builtins.exec" nocase ascii
    condition:
        2 of ($i* $e* $b*)
}

rule Pickle_OS_Subprocess_Abuse {
    meta:
        description = "Indicators of system/subprocess execution via pickle"
        author = "LordofTheBrines"
    strings:
        $s1 = "os.system" nocase ascii
        $s2 = "subprocess" nocase ascii
        $s3 = "sh -c" nocase ascii
    condition:
        any of them
}

rule Pickle_Marshal_Obfuscation {
    meta:
        description = "Marshal/bytecode payloads and base64 exec chains"
        author = "LordofTheBrines"
    strings:
        $m1 = "marshal.loads" nocase ascii
        $b64 = "base64.b64decode(" nocase ascii
        $bz2 = "bz2.decompress(" nocase ascii
        $zlib = "zlib.decompress(" nocase ascii
        $ex = "exec(" nocase ascii
    condition:
        $m1 or (($b64 or $bz2 or $zlib) and $ex)
}

rule Pickle_Pip_Install_Evasion {
    meta:
        description = "Pip installation strings embedded in pickle"
        author = "LordofTheBrines"
    strings:
        $p1 = "pip install" nocase ascii
        $p2 = "pip.main" nocase ascii
    condition:
        any of them
}

rule Pickle_Torch_Joblib_Gadget_Hints {
    meta:
        description = "Common gadget-family hints seen in torch/joblib artifacts"
        author = "LordofTheBrines"
    strings:
        $t1 = "torch.storage._load" ascii
        $t2 = "torch._utils._rebuild_tensor" ascii
        $j1 = "joblib" ascii
        $n1 = "numpy.core.multiarray" ascii
    condition:
        ($t1 and $t2) or ($j1 and $n1)
}

rule Pickle_Unicode_ZeroWidth_Obfuscation {
    meta:
        description = "Zero-width and bidi characters often used to hide keywords"
        author = "LordofTheBrines"
        notes = "ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, RLO U+202E"
    strings:
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
        $zwj  = { E2 80 8D }
        $rlo  = { E2 80 AE }
    condition:
        any of them
}

rule Pickle_Base64_Exec_Combinator {
    meta:
        description = "Explicit base64 decode + exec pattern"
        author = "LordofTheBrines"
    strings:
        $b1 = "base64.b64decode(" nocase ascii
        $e1 = "exec(" nocase ascii
    condition:
        $b1 and $e1
}

rule Pickle_RCE_Core
{
  meta:
    description = "Pickle RCE indicators (os/system/import indirection)"
    author = "LordofTheBrines"
    confidence = "high"
  strings:
    $a1 = "os.system" ascii wide nocase
    $a2 = "subprocess.Popen" ascii wide nocase
    $a3 = "__import__(" ascii wide
    $a4 = "getattr(__import__(" ascii wide
    $a5 = "builtins.exec" ascii wide nocase
    $a6 = "builtins.eval" ascii wide nocase
    $z0 = /\x80[\x02\x03\x04\x05]/  // pickle protocol 2..5
  condition:
    any of ($a*) and $z0
}

rule Pickle_Marshal_Obfuscation
{
  meta:
    description = "Marshal-based obfuscation seen in pickle payloads"
    author = "LordofTheBrines"
    confidence = "medium"
  strings:
    $m1 = "marshal.loads" ascii wide nocase
    $m2 = "marshal.load" ascii wide nocase
    // Long base64-like blob
    $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/
  condition:
    $m1 or $m2 or ($b64 and $m1)
}

rule Pickle_Pip_Install_Evasion
{
  meta:
    description = "pip-based installation attempt from pickle payload"
    author = "LordofTheBrines"
    confidence = "high"
  strings:
    $p1 = "pip install " ascii wide nocase
    $p2 = "pip.main(" ascii wide nocase
    $p3 = "pip._internal" ascii wide nocase
  condition:
    any of them
}

rule Pickle_Indirection_Strings
{
  meta:
    description = "Generic import indirection and code-eval hints"
    author = "LordofTheBrines"
    confidence = "medium"
  strings:
    $i1 = "getattr(__import__(" ascii wide
    $i2 = "eval(" ascii wide
    $i3 = "__builtins__" ascii wide
    $i4 = "builtins.__import__" ascii wide
    $i5 = "builtins.getattr" ascii wide
  condition:
    #i1 or #i2 or #i3 or #i4 or #i5
}

rule Pickle_Torch_Suspicious
{
  meta:
    description = "Suspicious Torch strings (pair with other signals)"
    author = "LordofTheBrines"
    confidence = "low"
  strings:
    $t1 = "torch" ascii wide nocase
    $t2 = "pytorch" ascii wide nocase
    $t3 = "/bin/sh" ascii wide
    $t4 = "bash -c" ascii wide
    $t5 = "subprocess" ascii wide
  condition:
    any of ($t*) and 1 of ($t3,$t4,$t5)
}

rule Pickle_Torch_Gadgets
{
  meta:
    description = "Torch serialization + exec hints"
    author = "LordofTheBrines"
    confidence = "medium"
  strings:
    $tt1 = "torch" ascii wide nocase
    $tt2 = "torch.serialization" ascii wide nocase
    $tt3 = "state_dict" ascii wide nocase
    $tt4 = "os.system" ascii wide nocase
    $tt5 = "subprocess" ascii wide nocase
    $z0 = /\x80[\x02-\x05]/
  condition:
    $tt1 and 1 of ($tt4,$tt5) and $z0
}

rule Pickle_Joblib_Gadgets
{
  meta:
    description = "Joblib/numpy gadget hints inside pickle"
    author = "LordofTheBrines"
    confidence = "medium"
  strings:
    $j1 = "joblib" ascii wide nocase
    $j2 = "numpy.core.multiarray" ascii wide nocase
    $j3 = "numpy.core.memmap" ascii wide nocase
    $j4 = "compressor" ascii wide nocase
    $z0 = /\x80[\x02-\x05]/
  condition:
    2 of ($j*) and $z0
}

rule Pickle_Base64_Exec
{
  meta:
    description = "base64 decode followed by exec/eval/compile"
    author = "LordofTheBrines"
    confidence = "high"
  strings:
    $b1 = "base64.b64decode" ascii wide nocase
    $e1 = "exec(" ascii wide nocase
    $e2 = "eval(" ascii wide nocase
    $e3 = "compile(" ascii wide nocase
  condition:
    $b1 and 1 of ($e1,$e2,$e3)
}

rule Pickle_Marshal_XOR
{
  meta:
    description = "marshal + XOR/base64 style obfuscation"
    author = "LordofTheBrines"
    confidence = "medium"
  strings:
    $m1 = "marshal.loads" ascii wide nocase
    $x1 = "xor" ascii wide nocase
    $b64 = /[A-Za-z0-9+\/]{60,}={0,2}/
  condition:
    $m1 and ($x1 or $b64)
}

rule Pickle_Unicode_ZeroWidth_Tricks
{
  meta:
    description = "Zero-width & bidi control characters used to obfuscate tokens"
    author = "LordofTheBrines"
    confidence = "low"
  strings:
    $zw1 = /\xE2\x80[\x8B-\x8F]/      // ZWSP..RLM
    $zw2 = /\xE2\x80[\xAA-\xAE]/      // LRE..RLO
    $zw3 = /\xE2\x81[\xA0-\xAF]/      // word joiners range
  condition:
    any of them
}

rule Pickle_Zip_Name_Tamper
{
  meta:
    description = "ZIP filename tampering hints (dir traversal & unicode control)"
    author = "LordofTheBrines"
    confidence = "low"
  strings:
    $z1 = "../" ascii
    $z2 = "..\\" ascii
    $z3 = "%2f" ascii nocase
    $z4 = "%5c" ascii nocase
    $z5 = /PK\x03\x04/  // ZIP local header present
  condition:
    $z5 and (any of ($z1,$z2,$z3,$z4))
}


