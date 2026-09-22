"""Sidecar cache integrity: sealed revocation conclusions must never depend
on the auxiliary scope indexes.

The ``*.revindex.json`` / ``*.nameindex.json`` sidecars are derived caches
that live outside the database and are not part of the sealed content
digest. If a sidecar is missing, truncated, corrupt, structurally valid but
content-substituted, or comes from a store sealed before sidecar
authentication, a cold process must fall back to exact eager blob parsing and
reach the same verdict, byte-for-byte.

The attack under test: after sealing, only a *scope value* in the revocation
sidecar (a CRL issuer Name / AKI, or an OCSP CertID serial) is replaced with
unrelated legal Base64. The JSON format, version and the full revocation
digest universe stay intact. A cached (warm) adjudication is unaffected; the
contradiction appears only after close/reopen on an *uncached* request.
"""
import glob
import hashlib
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app import canonical
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _request(leaf, root_fp, lk, artifact=b"artifact"):
    d = hashlib.sha256(artifact).digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return {"artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": "1.2.840.10045.4.3.2", "signed_at": SIGNED,
            "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(leaf)),
            "initial_policies": [ANY], "trust_anchors": [root_fp]}


class SetBuilder:
    def __init__(self, store, sid):
        self.store = store
        self.sid = sid
        store.create_set(sid, "c")
        self.rows = []

    def cert(self, c, ref=None):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": ref or "c" + fp_of(d)[:14],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": RECEIVED})

    def rev(self, o, ref, kind="crl"):
        d = pf.der(o)
        self.store.put_blob(d)
        self.rows.append({"client_ref": ref, "kind": kind,
                          "content_sha256": fp_of(d),
                          "received_at": RECEIVED})
        return fp_of(d)

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)


def _chain():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    return rk, ck, lk, root, ca, leaf


def _revindex_path(data):
    return glob.glob(os.path.join(data, "packages", "*.revindex.json"))[0]


def _nameindex_path(data):
    return glob.glob(os.path.join(data, "packages", "*.nameindex.json"))[0]


def _leaf_conclusion(res, leaf_fp):
    for snap in res.get("revocation_snapshot", []):
        if snap["certificate"] == leaf_fp:
            return snap["conclusion"]
    return None


def _build_revoked_crl_set(data, *, with_noise=True):
    """Root + CA + code-signing leaf; root GOOD CRL, older GOOD CA CRL and a
    newer CA CRL that revokes the leaf. Returns handles needed by tests."""
    store = Store(data)
    sid = "es_sidecar_revoked_0000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "rootcrl")
    b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 200,
                       next_update=SIGNED + 50, crl_number=1), "older-good")
    newer = pf.build_crl(ca, ck,
                         [(leaf.serial_number, SIGNED - 10, "key_compromise")],
                         last_update=SIGNED - 100, next_update=SIGNED + 100,
                         crl_number=2)
    newer_fp = b.rev(newer, "newer-revoked")
    noise_fps = set()
    if with_noise:
        nk = pf.gen_key()
        noise_ca = pf.build_cert("Noise CA", None, nk, nk, is_ca=True,
                                 key_usage=("keyCertSign", "cRLSign"),
                                 policies=[ANY], self_signed=True)
        b.cert(noise_ca, "noise-ca")
        for i in range(8):
            o = pf.build_crl(noise_ca, nk, [], last_update=SIGNED - 300 + i,
                             next_update=SIGNED + 50_000 + i, crl_number=i + 1)
            noise_fps.add(b.rev(o, f"noise-{i}"))
    manifest = b.seal()
    store.close()
    return {
        "sid": sid, "manifest": manifest, "root": root, "leaf": leaf,
        "rk": rk, "ck": ck, "lk": lk, "newer_fp": newer_fp,
        "noise_fps": noise_fps,
    }


def _cold_adjudicate(data, ctx, trace_reads=False):
    store = Store(data)
    read = set()
    orig = Store.get_blob
    if trace_reads:
        def traced(self, digest):
            read.add(digest)
            return orig(self, digest)

        Store.get_blob = traced
    try:
        req = _request(ctx["leaf"], fp_of(pf.der(ctx["root"])), ctx["lk"])
        res = adjudicate(store, ctx["sid"], req)
    finally:
        Store.get_blob = orig
    # Package build intentionally bundles the whole revocation universe; do it
    # OUTSIDE the trace so ``read`` reflects adjudication materialization only.
    pkg = build_package(store, res, ctx["manifest"])
    return store, res, pkg, read


def test_intact_sidecar_stays_lazy(tmp_path):
    data = str(tmp_path / "data")
    ctx = _build_revoked_crl_set(data)
    store, res, _pkg, read = _cold_adjudicate(data, ctx, trace_reads=True)
    # Correct verdict, and zero unrelated noise DER reads on the cold path.
    assert res["verdict"]["status"] == "REJECTED"
    assert not (read & ctx["noise_fps"])
    store.close()


@pytest.mark.parametrize("mode", [
    "issuer_scope_replaced",
    "aki_scope_replaced",
    "truncated",
    "garbage_bytes",
    "deleted",
    "version_bumped",
])
def test_revocation_sidecar_tamper_cannot_flip_revoked(tmp_path, mode):
    data = str(tmp_path / "data")
    ctx = _build_revoked_crl_set(data)
    path = _revindex_path(data)

    if mode in ("issuer_scope_replaced", "aki_scope_replaced"):
        idx = json.load(open(path))
        for row in idx["crls"]:
            if row["s"] == ctx["newer_fp"]:
                if mode == "issuer_scope_replaced":
                    # Unrelated, structurally legal Name DER in Base64.
                    row["i"] = canonical_dummy_name()
                else:
                    row["a"] = canonical_dummy_aki()
        # JSON/version intact; every revocation digest still enumerated.
        with open(path, "w") as f:
            json.dump(idx, f)
    elif mode == "truncated":
        raw = open(path, "rb").read()
        with open(path, "wb") as f:
            f.write(raw[: len(raw) // 4])
    elif mode == "garbage_bytes":
        with open(path, "wb") as f:
            f.write(b"\x00\x01not-json-at-all\xff")
    elif mode == "deleted":
        os.remove(path)
    elif mode == "version_bumped":
        idx = json.load(open(path))
        idx["version"] = 99
        with open(path, "w") as f:
            json.dump(idx, f)

    # Tamper forces the exact eager fallback: unrelated noise DERs are read
    # this time, but the verdict is unchanged and the package re-verifies.
    store, res, _pkg, read = _cold_adjudicate(data, ctx, trace_reads=True)
    leaf_fp = fp_of(pf.der(ctx["leaf"]))
    assert res["verdict"]["status"] == "REJECTED", mode
    assert _leaf_conclusion(res, leaf_fp) == "REVOKED", mode
    assert read >= ctx["noise_fps"], mode  # eager fallback really happened

    pkg_path = tmp_path / "pkg.zip"
    with open(pkg_path, "wb") as f:
        f.write(_pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    store.close()


def canonical_dummy_name() -> str:
    import base64

    return base64.b64encode(b"\x30\x06\x31\x04\x41\x41").decode()


def canonical_dummy_aki() -> str:
    import base64

    return base64.b64encode(b"\x11" * 20).decode()


def test_ocsp_serial_scope_replaced_cannot_flip_revoked(tmp_path):
    data = str(tmp_path / "data")
    store = Store(data)
    sid = "es_sidecar_ocsp_00000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    # GOOD CA/root CRLs keep the chain clear; leaf revocation rides on OCSP.
    b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 400,
                       next_update=SIGNED + 400, crl_number=1), "ca-crl")
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 400,
                       next_update=SIGNED + 400, crl_number=1), "root-crl")
    # Older GOOD OCSP and a newer REVOKED OCSP for the same leaf.
    good = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 150,
                         next_update=SIGNED + 150, hash_alg=hashes.SHA256())
    revoked = pf.build_ocsp(leaf, ca, ck, "revoked",
                            revocation_time=SIGNED - 10,
                            this_update=SIGNED - 50, next_update=SIGNED + 150,
                            hash_alg=hashes.SHA256())
    b.rev(good, "ocsp-good", kind="ocsp")
    revoked_fp = b.rev(revoked, "ocsp-revoked", kind="ocsp")
    manifest = b.seal()
    store.close()

    # Tamper: point the revoking OCSP row at an unrelated CertID serial only.
    path = _revindex_path(data)
    idx = json.load(open(path))
    for row in idx["ocsps"]:
        if row["s"] == revoked_fp:
            row["n"] = [987_654_321]
    with open(path, "w") as f:
        json.dump(idx, f)

    ctx = {"sid": sid, "manifest": manifest, "root": root, "leaf": leaf,
           "rk": rk, "ck": ck, "lk": lk}
    store, res, pkg, _read = _cold_adjudicate(data, ctx)
    leaf_fp = fp_of(pf.der(leaf))
    assert res["verdict"]["status"] == "REJECTED"
    assert _leaf_conclusion(res, leaf_fp) == "REVOKED"
    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    store.close()


def test_name_sidecar_tamper_cannot_hide_issuer(tmp_path):
    """A GOOD chain must still validate when the name index is tampered so as
    to hide the CA's subject-name bucket (the lazy graph would otherwise find
    no path to anchor)."""
    data = str(tmp_path / "data")
    store = Store(data)
    sid = "es_sidecar_name_00000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "ca-crl")
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "root-crl")
    manifest = b.seal()
    store.close()

    # Replace the whole name index with one that maps no issuer (valid JSON,
    # wrong digest). Signature mismatch forces eager graph rebuild.
    path = _nameindex_path(data)
    doc = json.load(open(path))
    doc["names"] = {}
    with open(path, "w") as f:
        json.dump(doc, f)

    store = Store(data)
    res = adjudicate(store, sid,
                     _request(leaf, fp_of(pf.der(root)), lk))
    assert res["verdict"]["status"] == "VALID"
    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(build_package(store, res, manifest))
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    store.close()


def test_legacy_sealed_store_without_sidecar_auth_uses_eager(tmp_path):
    """A store sealed before authenticated sidecars: the manifest carries no
    sidecar digests and the files use the v1 layout. Cold reads must still
    reach the correct REVOKED verdict (exact eager fallback)."""
    data = str(tmp_path / "data")
    ctx = _build_revoked_crl_set(data, with_noise=False)
    sid = ctx["sid"]

    # Rewind to the legacy on-disk representation.
    rev_path = _revindex_path(data)
    rev = json.load(open(rev_path))
    rev["version"] = 1
    with open(rev_path, "w") as f:
        json.dump(rev, f)
    name_path = _nameindex_path(data)
    name_doc = json.load(open(name_path))
    with open(name_path, "w") as f:  # legacy flat mapping
        json.dump(name_doc["names"], f)

    store = Store(data)
    row = store.get_set(sid)
    manifest = json.loads(row["manifest_json"])
    # Rewind the sealed manifest to the legacy form (no sidecar digests).
    manifest.pop("sidecars", None)
    with store._lock:
        store._conn.execute(
            "UPDATE sets SET manifest_json=? WHERE id=?",
            (canonical.dumps(manifest).decode(), sid))
        store._conn.commit()
    store.close()

    ctx["manifest"] = manifest
    store, res, pkg, read = _cold_adjudicate(data, ctx, trace_reads=True)
    leaf_fp = fp_of(pf.der(ctx["leaf"]))
    assert res["verdict"]["status"] == "REJECTED"
    assert _leaf_conclusion(res, leaf_fp) == "REVOKED"
    # Legacy store => eager: the revoking CRL blob is certainly read.
    assert ctx["newer_fp"] in read
    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    store.close()


def test_cold_and_second_instance_share_correct_verdict(tmp_path):
    """Two independent Store views of one sealed volume (multi-instance) both
    adjudicate REVOKED even after the sidecar is tampered between them."""
    data = str(tmp_path / "data")
    ctx = _build_revoked_crl_set(data, with_noise=False)

    s1 = Store(data)
    req = _request(ctx["leaf"], fp_of(pf.der(ctx["root"])), ctx["lk"])
    r1 = adjudicate(s1, ctx["sid"], req)
    assert r1["verdict"]["status"] == "REJECTED"
    s1.close()

    # Tamper after instance 1 sealed its warm view.
    path = _revindex_path(data)
    idx = json.load(open(path))
    for row in idx["crls"]:
        if row["s"] == ctx["newer_fp"]:
            row["i"] = canonical_dummy_name()
    with open(path, "w") as f:
        json.dump(idx, f)

    s2 = Store(data)  # cold second instance
    # Fresh request digest => cache miss => cold loader path, not DB replay.
    req2 = _request(ctx["leaf"], fp_of(pf.der(ctx["root"])), ctx["lk"],
                    artifact=b"different-artifact")
    r2 = adjudicate(s2, ctx["sid"], req2)
    leaf_fp = fp_of(pf.der(ctx["leaf"]))
    assert r2["verdict"]["status"] == "REJECTED"
    assert _leaf_conclusion(r2, leaf_fp) == "REVOKED"
    s2.close()
