"""Integrity of the sealed revocation-scope sidecars.

The revindex/nameindex sidecars are pure acceleration hints: they let a cold
process bound revocation materialization to in-scope objects without reading
unrelated DER blobs. Their canonical bytes are therefore anchored (SHA-256) in
the sealed database row at seal time.

If a sidecar is missing, truncated, structurally corrupt, or any of its
content (issuer Name/AKI, OCSP serials, in/out-of-profile verdict, seal-time
problem record) is replaced with otherwise legal values, a cold process must:

* still reach the exact verdict the sealed blobs dictate (byte-identical to
  the warm process and to the offline package review) — here REJECTED with
  the code-signing leaf REVOKED;
* take the exact eager blob-parse path (security over performance: the lazy
  guarantee is only promised for intact inputs);
* self-heal: rebuild the sidecar from sealed blobs and re-anchor it, so the
  next cold process is lazy again.

Legacy stores (sealed before anchors existed; empty/missing anchor column)
keep working via the same fallback.
"""
import base64
import glob
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from tests.test_lazy_revocation import (
    ANY, SIGNED, SetBuilder, _build_noise_set, _chain, _request,
)
from app import metrics
from app.adjudge import adjudicate
from app.certmodel import fp_of
from app.package import build_package
from app.storage import Store
from verify.verify_package import verify_package


def _revoked_set(store_path, *, with_noise=12):
    """root + issuing CA + code-signing leaf; root GOOD CRL; older GOOD CA
    CRL; newer CA CRL that revokes the leaf; plus unrelated Noise-CA CRLs
    (which must never hide the decisive revocation)."""
    store = Store(store_path)
    sid = "es_sidecar_tamper_000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    b.rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1), "rcrl")
    old_fp = b.rev(pf.build_crl(ca, ck, [], last_update=SIGNED - 200,
                                next_update=SIGNED + 100, crl_number=10), "old")
    revoked = pf.build_crl(
        ca, ck, [(leaf.serial_number, SIGNED - 50, "key_compromise")],
        last_update=SIGNED - 100, next_update=SIGNED + 100, crl_number=11)
    revoked_fp = b.rev(revoked, "new")
    noise_fps = set()
    nk = pf.gen_key()
    noise_ca = pf.build_cert("Noise CA", None, nk, nk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                             self_signed=True)
    b.cert(noise_ca, "noise-ca")
    for i in range(with_noise):
        o = pf.build_crl(noise_ca, nk, [], last_update=SIGNED - 500 + i,
                         next_update=SIGNED + 50_000 + i, crl_number=i + 1)
        noise_fps.add(b.rev(o, f"noise-{i}"))
    manifest = b.seal()
    store.close()
    keys = (rk, ck, lk, root, ca, leaf)
    return (sid, keys, {"revoked": revoked_fp, "old": old_fp},
            noise_fps, manifest)


def _sidecar(data, suffix):
    return glob.glob(os.path.join(data, "packages", f"*.{suffix}.json"))[0]


def _reopen_traced(data, sid, keys, artifact=b"cold-artifact"):
    rk, ck, lk, root, ca, leaf = keys
    store = Store(data)
    read = set()
    orig = Store.get_blob

    def traced(self, digest):
        read.add(digest)
        return orig(self, digest)

    metrics.reset()
    Store.get_blob = traced
    try:
        res = adjudicate(store, sid,
                         _request(leaf, fp_of(pf.der(root)), lk, artifact=artifact))
    finally:
        Store.get_blob = orig
    return store, res, read


def _assert_revoked(res, leaf_fp=None):
    assert res["verdict"]["status"] == "REJECTED", res["verdict"]
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    if leaf_fp is None:
        revoked = [r for r in snap.values() if r["conclusion"] == "REVOKED"]
        assert len(revoked) == 1, [r["conclusion"] for r in snap.values()]
        leaf_res = revoked[0]
    else:
        leaf_res = snap[leaf_fp]
        assert leaf_res["conclusion"] == "REVOKED"
    sel = leaf_res["selected_evidence"]
    assert sel["kind"] == "crl"
    return leaf_res


# ------------------------------------------------------------ CRL tampering
def test_replace_newer_crl_issuer_scope_cold(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, fps, noise_fps, manifest = _revoked_set(data)
    rk, ck, lk, root, ca, leaf = keys
    # Warm baseline: REJECTED / REVOKED.
    warm_store = Store(data)
    warm = adjudicate(warm_store, sid,
                      _request(leaf, fp_of(pf.der(root)), lk, artifact=b"warm"))
    _assert_revoked(warm)
    warm_store.close()

    path = _sidecar(data, "revindex")
    idx = json.load(open(path))
    for row in idx["crls"]:
        if row["s"] == fps["revoked"]:
            row["i"] = base64.b64encode(os.urandom(32)).decode()
    with open(path, "w") as f:
        json.dump(idx, f)

    store, cold, read = _reopen_traced(data, sid, keys)
    _assert_revoked(cold)
    # The decisive CRL was materialized despite the bogus scope hint...
    assert fps["revoked"] in read
    parsed = set(metrics.snapshot()[sid]["crl_full_parsed"])
    assert fps["revoked"] in parsed
    # ...and the offline package review of the warm result stays byte-exact.
    pkg = build_package(store, warm, manifest)
    zp = tmp_path / "pkg.zip"
    zp.write_bytes(pkg)
    report = verify_package(str(zp))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    store.close()


def test_replace_crl_aki_scope_cold(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, fps, _noise, _m = _revoked_set(data)
    path = _sidecar(data, "revindex")
    idx = json.load(open(path))
    for row in idx["crls"]:
        if row["s"] == fps["revoked"]:
            row["a"] = base64.b64encode(os.urandom(20)).decode()
    with open(path, "w") as f:
        json.dump(idx, f)
    store, cold, read = _reopen_traced(data, sid, keys)
    _assert_revoked(cold)
    assert fps["revoked"] in read
    store.close()


def test_flip_parse_verdict_flag_cold(tmp_path):
    """Turn the decisive, in-profile CRL's row into a seal-time rejection
    (e=1) with a fabricated problem dict: still legal JSON, verdict flag
    inverted. The anchor mismatch must force eager parsing."""
    data = str(tmp_path / "data")
    sid, keys, fps, _noise, _m = _revoked_set(data)
    path = _sidecar(data, "revindex")
    idx = json.load(open(path))
    for row in idx["crls"]:
        if row["s"] == fps["revoked"]:
            row["e"] = 1
            row["i"] = row["a"] = None
            row["p"] = {"code": "UNSUPPORTED", "message": "forged",
                        "detail": {}}
    with open(path, "w") as f:
        json.dump(idx, f)
    store, cold, _read = _reopen_traced(data, sid, keys)
    _assert_revoked(cold)
    # The forged parse rejection must not appear in dispositions.
    rejected = {p["sha256"]: p
                for p in cold["evidence_disposition"]["parse_rejected"]}
    assert fps["revoked"] not in rejected
    store.close()


def test_truncated_and_missing_rev_sidecar_cold(tmp_path):
    for mode in ("truncate", "delete"):
        data = str(tmp_path / f"data-{mode}")
        sid, keys, fps, _noise, _m = _revoked_set(data)
        path = _sidecar(data, "revindex")
        if mode == "truncate":
            raw = open(path, "rb").read()
            with open(path, "wb") as f:
                f.write(raw[: len(raw) // 2])
        else:
            os.remove(path)
        store, cold, read = _reopen_traced(
            data, sid, keys, artifact=f"art-{mode}".encode())
        _assert_revoked(cold)
        assert fps["revoked"] in read
        store.close()


# ------------------------------------------------------------ OCSP tampering
def test_replace_ocsp_serials_scope_cold(tmp_path):
    store = Store(str(tmp_path / "data1"))
    sid = "es_sidecar_ocsp_00000000000000000000000001"
    b = SetBuilder(store, sid)
    rk, ck, lk, root, ca, leaf = _chain()
    for c in (root, ca, leaf):
        b.cert(c)
    revoked_oc = pf.build_ocsp(
        leaf, ca, ck, "revoked", this_update=SIGNED - 100,
        next_update=SIGNED + 100, revocation_time=SIGNED - 50,
        reason="key_compromise", hash_alg=hashes.SHA256())
    fp = b.rev(revoked_oc, "ocsp", kind="ocsp")
    b.seal()
    store.close()

    path = _sidecar(str(tmp_path / "data1"), "revindex")
    idx = json.load(open(path))
    for row in idx["ocsps"]:
        if row["s"] == fp:
            row["n"] = [999_999_999]
    with open(path, "w") as f:
        json.dump(idx, f)

    store2 = Store(str(tmp_path / "data1"))
    res = adjudicate(store2, sid,
                     _request(leaf, fp_of(pf.der(root)), lk, artifact=b"c"))
    assert res["verdict"]["status"] == "REJECTED"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    assert snap[fp_of(pf.der(leaf))]["conclusion"] == "REVOKED"
    assert fp in set(metrics.snapshot()[sid]["ocsp_full_parsed"])
    store2.close()


# ------------------------------------------------------------ name sidecar
def test_tampered_name_sidecar_rebuilds(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, _ = _build_noise_set(data)
    rk, ck, lk, root, ca, leaf = keys
    path = _sidecar(data, "nameindex")
    idx = json.load(open(path))
    # Drop the CA subject bucket: without the fallback path construction
    # could no longer find leaf -> CA.
    ca_name = base64.b64encode(ca.subject.public_bytes()).decode()
    idx.pop(ca_name, None)
    with open(path, "w") as f:
        json.dump(idx, f)
    store, cold, _read = _reopen_traced(data, sid, keys)
    assert cold["verdict"]["status"] == "VALID"
    store.close()


# ------------------------------------------------------------ self-heal
def test_self_heal_restores_lazy_path(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, fps, noise_fps, _m = _revoked_set(data)
    path = _sidecar(data, "revindex")
    idx = json.load(open(path))
    for row in idx["crls"]:
        if row["s"] == fps["revoked"]:
            row["i"] = base64.b64encode(os.urandom(32)).decode()
    with open(path, "w") as f:
        json.dump(idx, f)

    # First cold process: eager fallback parses everything and self-heals.
    store, cold, read = _reopen_traced(data, sid, keys, artifact=b"one")
    _assert_revoked(cold)
    assert read & noise_fps  # degraded: eager touched noise this once
    # The rebuilt sidecar is present and re-anchored.
    assert os.path.getsize(path) > 0
    row = store.get_set(sid)
    anchors = json.loads(row["sidecar_anchors"])
    assert anchors["revindex"] == hashlib.sha256(open(path, "rb").read()) \
        .hexdigest()
    store.close()

    # Second cold process: anchor matches again -> lazy, noise never read;
    # verdict unchanged and now identical to the warm process byte-for-byte.
    store2, cold2, read2 = _reopen_traced(data, sid, keys, artifact=b"two")
    _assert_revoked(cold2)
    assert not (read2 & noise_fps)
    parsed = set(metrics.snapshot()[sid]["crl_full_parsed"])
    assert fps["revoked"] in parsed and not (parsed & noise_fps)
    store2.close()


# ------------------------------------------------------------ legacy stores
def test_legacy_store_without_anchors_still_correct_and_heals(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, fps, noise_fps, _m = _revoked_set(data)
    # Simulate a store sealed before anchors existed (column migrated in,
    # value NULL): the sidecar must not be trusted on its own.
    store = Store(data)
    store._conn.execute("UPDATE sets SET sidecar_anchors=NULL")
    store._conn.commit()
    store.close()

    store, cold, read = _reopen_traced(data, sid, keys, artifact=b"leg")
    _assert_revoked(cold)
    assert read & noise_fps  # slow legacy path this once
    row = store.get_set(sid)
    anchors = json.loads(row["sidecar_anchors"])
    assert set(anchors) == {"nameindex", "revindex"}
    store.close()

    # Subsequent cold read uses the healed, anchored sidecars lazily.
    store2, cold2, read2 = _reopen_traced(data, sid, keys, artifact=b"leg2")
    _assert_revoked(cold2)
    assert not (read2 & noise_fps)
    store2.close()


# ------------------------------------------------- intact-input performance
def test_intact_sidecar_still_skips_unrelated_crls(tmp_path):
    data = str(tmp_path / "data")
    sid, keys, target, noise_fps, _ = _build_noise_set(data)
    store, res, read = _reopen_traced(data, sid, keys)
    assert res["verdict"]["status"] == "VALID"
    assert not (read & noise_fps)
    parsed = set(metrics.snapshot()[sid]["crl_full_parsed"])
    assert parsed <= target and parsed
    store.close()
