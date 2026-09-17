#!/usr/bin/env python3
"""Set a code-signing trust setting for a certificate by editing the user trust list.

`security add-trusted-cert` always raises an authorization dialog ("You are making changes to
your Certificate Trust Settings"), so it cannot be used from a script that must not block.
`security trust-settings-import` performs the same write without prompting, so this tool
transforms the trust list directly and imports it.

Usage:
    set-trust.py add    <cert.pem> [<cert.pem> ...]
    set-trust.py drop   <CN> [<CN> ...]
    set-trust.py list
"""
import datetime
import plistlib
import subprocess
import sys
import tempfile
import os

# The trust settings are keyed by the certificate's SHA-1; issuerName holds the DER-encoded
# Name, and trustSettings carries the policy list. OIDs observed in the imported form.
CODESIGN_POLICY_OID = bytes.fromhex("2a864886f763640110")  # ..1.16, the codeSign policy


def run(args: list[str], text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=text)


def export(path: str) -> None:
    r = run(["security", "trust-settings-export", path])
    if r.returncode != 0:
        sys.exit(f"trust-settings-export failed: {r.stderr.strip()}")


def do_import(path: str) -> None:
    r = run(["security", "trust-settings-import", path])
    if r.returncode != 0:
        sys.exit(f"trust-settings-import failed: {r.stderr.strip()}")


def load(path: str) -> dict:
    with open(path, "rb") as f:
        return plistlib.load(f)


def cert_fields(pem: str) -> tuple[str, bytes, bytes]:
    """Return (sha1_hex_upper, issuerName DER, serialNumber bytes) for a certificate."""
    import hashlib
    der = run(["openssl", "x509", "-in", pem, "-outform", "DER"], text=False).stdout
    sha1 = hashlib.sha1(der).hexdigest().upper()
    issuer_der, serial = _issuer_and_serial(der)
    return sha1, issuer_der, serial


def _issuer_and_serial(der: bytes) -> tuple[bytes, bytes]:
    """Minimal DER walk to the issuer field of a Certificate (SEQUENCE { tbs, sigalg, sig })."""
    def tlv(b: bytes, i: int):
        tag = b[i]
        i += 1
        ln = b[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(b[i:i + n], "big")
            i += n
        return tag, b[i:i + ln], i + ln

    _, cert, _ = tlv(der, 0)                 # Certificate
    _, tbs, _ = tlv(cert, 0)                 # TBSCertificate
    i = 0
    tag, val, i = tlv(tbs, i)                # [0] version (optional)
    if tag == 0xA0:
        tag, val, i = tlv(tbs, i)            # serialNumber
    tag, ser, i = tlv(tbs, i)                # serialNumber
    tag, val, i = tlv(tbs, i)                # signature AlgorithmIdentifier
    tag, issuer, i = tlv(tbs, i)             # issuer Name  <-- what we want
    return issuer, ser


def cmd_add(pems: list[str]) -> int:
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "t.plist")
    export(src)
    d = load(src)
    tl = d.setdefault("trustList", {})
    added = 0
    for pem in pems:
        sha1, issuer_der, serial = cert_fields(pem)
        if sha1 in tl:
            print(f"  {pem}: already present ({sha1[:12]}...)")
            continue
        tl[sha1] = {
            "issuerName": issuer_der,
            "modDate": datetime.datetime.now(),
            "serialNumber": serial,
            "trustSettings": [{
                "kSecTrustSettingsPolicy": CODESIGN_POLICY_OID,
                "kSecTrustSettingsPolicyName": "CodeSigning",
            }],
        }
        added += 1
        print(f"  {pem}: added as {sha1[:12]}...")
    dst = os.path.join(tmp, "out.plist")
    with open(dst, "wb") as f:
        plistlib.dump(d, f)
    do_import(dst)
    print(f"  imported ({added} added, {len(tl)} total entries)")
    return 0


def cmd_drop(names: list[str]) -> int:
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "t.plist")
    export(src)
    d = load(src)
    tl = d.get("trustList", {})
    want = [n.encode() for n in names]
    kept, removed = {}, []
    for k, v in tl.items():
        blob = v.get("issuerName") or b""
        if any(w in blob for w in want):
            removed.append(k)
        else:
            kept[k] = v
    d["trustList"] = kept
    dst = os.path.join(tmp, "out.plist")
    with open(dst, "wb") as f:
        plistlib.dump(d, f)
    do_import(dst)
    print(f"  removed {len(removed)} entr{'y' if len(removed)==1 else 'ies'} "
          f"matching {', '.join(names)}; {len(kept)} remain")
    return 0


def cmd_list() -> int:
    r = run(["security", "dump-trust-settings"])
    print(r.stdout or r.stderr)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "add":
        sys.exit(cmd_add(args))
    if cmd == "drop":
        sys.exit(cmd_drop(args))
    if cmd == "list":
        sys.exit(cmd_list())
    sys.exit(__doc__)