"""Materialize a sealed evidence set into lazily parsed indexes.

Both certificates and revocation objects are parsed *lazily and only when
they can concern the certificate under adjudication*:

* certificates are parsed on first access (the acceptance load has 100k certs
  but adjudicates a handful of leaves);
* CRLs are fully DER-parsed only when their issuer Name and AKI match a
  certificate whose revocation is being evaluated, and OCSP responses only
  when they carry a CertID for that certificate's serial.

At seal time every revocation object is fully parsed exactly once (seal
already x509-loads every CRL for the entry-count limit), and the resulting
scope (CRL issuer Name/AKI; OCSP CertID serials) plus the in/out-of-profile
verdict is stored in a sidecar index. A cold process therefore bounds scope
from the sidecar and never even reads an unrelated revocation DER after a
restart, instance switch or adjudication-cache miss. Richer checks (IDP
distribution point, onlyContains, certID hashes, signatures, validity
windows) still run through the full parser during adjudication, so verdicts
and evidence dispositions are identical to eager parsing.

The sidecars are acceleration hints, never authority: the SHA-256 of their
exact canonical bytes is recorded in the sealed database row
(``sidecar_anchors`` — storage independent of the hint files). A cold read
accepts a sidecar only when its bytes match the anchor and its rows both
exactly cover the sealed universe and are structurally well formed. If the
sidecar is absent, truncated, corrupt, has any scope/verdict value replaced,
or the store predates anchors (old sealed sets / offline package review),
the loader falls back to exact eager parsing of the sealed blobs and then
self-heals the sidecar and anchor. Tampering with the auxiliary scope
information therefore cannot change a sealed verdict: the result always
matches a full re-parse byte-for-byte.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from . import canonical
from . import evidence as ev
from . import metrics as _metrics
from .certmodel import ParsedCert, parse_certificate
from .errors import MalformedEvidenceError, UnsupportedError
from .graph import CertGraph

REV_INDEX_VERSION = 1


def build_name_index(cert_digests: list[str], get_blob) -> dict[str, list[str]]:
    """Seal-time cheap subject-name index: raw Name DER (base64) -> digests.

    Shared by sealing and by the cold-start self-heal migration so both emit
    byte-identical sidecars."""
    from .certmodel import cheap_names
    from .errors import MalformedEvidenceError as _MEE

    name_index: dict[str, list[str]] = {}
    for digest in cert_digests:
        try:
            _issuer, subject = cheap_names(get_blob(digest))
        except _MEE:
            continue
        name_index.setdefault(base64.b64encode(subject).decode(), []).append(digest)
    return name_index


def build_revocation_index(crls: list[dict], ocsps: list[dict],
                           get_blob) -> tuple[dict, int]:
    """Fully parse every revocation object once and build the scope/profile
    sidecar. Returns ``(index, total_crl_entries)``. Deterministic: callers
    pass the SHA-sorted sealed content lists, so the canonical bytes are
    identical across instances, restarts and the self-heal migration."""
    import base64 as _b64

    from cryptography import x509 as _x509

    rev_index = {"version": REV_INDEX_VERSION, "crls": [], "ocsps": []}
    total_entries = 0
    for x in crls:
        digest = x["sha256"]
        raw = get_blob(digest)
        # Entry-count resource limit (a structurally unloadable CRL fails
        # here, exactly as before lazy materialization).
        total_entries += len(_x509.load_der_x509_crl(raw))
        obj, problem = ev.review_crl(raw, x["received_at"])
        if problem is not None:
            rev_index["crls"].append(
                {"s": digest, "i": None, "a": None, "e": 1, "p": problem})
        else:
            scope = ev.crl_scope_from_obj(obj)
            rev_index["crls"].append({
                "s": digest,
                "i": _b64.b64encode(scope.issuer_name).decode(),
                "a": _b64.b64encode(scope.aki).decode()
                if scope.aki is not None else None, "e": 0})
    for x in ocsps:
        digest = x["sha256"]
        obj, problem = ev.review_ocsp(get_blob(digest), x["received_at"])
        if problem is not None:
            rev_index["ocsps"].append(
                {"s": digest, "n": None, "e": 1, "p": problem})
        else:
            scope = ev.ocsp_scope_from_obj(obj)
            rev_index["ocsps"].append(
                {"s": digest, "n": sorted(scope.serials), "e": 0})
    return rev_index, total_entries


class LoadedSet:
    def __init__(self, store, manifest: dict):
        self.store = store
        self.manifest = manifest
        self.content = manifest["content"]
        self._parsed: dict[str, ParsedCert] = {}
        self.crls: dict[str, ev.CrlObject] = {}
        self.ocsps: dict[str, ev.OcspObject] = {}
        self.parse_problems: list[dict] = []
        # Lazily materialized revocation objects (None == failed to parse).
        self._crl_cache: dict[str, ev.CrlObject | None] = {}
        self._ocsp_cache: dict[str, ev.OcspObject | None] = {}
        self._rev_index_loaded = False
        # issuer Name DER -> [(digest, aki|None)]; serial -> [digest]
        self._crl_by_issuer: dict[bytes, list[tuple[str, bytes | None]]] = {}
        self._ocsp_by_serial: dict[int, list[str]] = {}
        self._crl_received: dict[str, int] = {}
        self._ocsp_received: dict[str, int] = {}

    @classmethod
    def from_store(cls, store, manifest: dict) -> "LoadedSet":
        return cls(store, manifest)

    def get_blob(self, digest: str) -> bytes:
        return self.store.get_blob(digest)

    # -------------------------------------------------------- certificates
    def cert(self, digest: str) -> ParsedCert | None:
        if digest in self._parsed:
            return self._parsed[digest]
        try:
            data = self.get_blob(digest)
            pc = parse_certificate(data)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._parsed[digest] = None  # type: ignore[assignment]
            self.parse_problems.append({
                "sha256": digest, "kind": "certificate",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self._parsed[digest] = pc
        return pc

    def all_cert_digests(self) -> list[str]:
        return list(self.content["certificates"])

    def build_graph(self, anchor_digests: set[str]) -> CertGraph:
        """Parse only anchor certs eagerly; everything else stays lazy."""
        certs: dict[str, ParsedCert] = {}
        for d in anchor_digests:
            pc = self.cert(d)
            if pc is not None:
                certs[d] = pc

        class LazyGraph(CertGraph):
            def __init__(self_inner, loader, anchor_ds):
                self_inner.loader = loader
                self_inner.anchor_ds = anchor_ds
                self_inner.certs = certs
                self_inner.by_name = {}
                self_inner.by_name_key = {}
                self_inner._edge_cache = {}

            def _materialize(self_inner, digest: str) -> ParsedCert | None:
                if digest in self_inner.certs:
                    return self_inner.certs[digest]
                pc = self_inner.loader.cert(digest)
                if pc is None:
                    return None
                self_inner.certs[digest] = pc
                self_inner.by_name.setdefault(pc.subject_der, []).append(digest)
                self_inner.by_name_key.setdefault(
                    (pc.subject_der, pc.spki_bitstring), []).append(digest)
                return pc

            def get_cert(self_inner, digest: str) -> ParsedCert | None:
                return self_inner._materialize(digest)

        graph = LazyGraph(self, anchor_digests)

        # Override candidate lookup to lazily parse: find certs whose SUBJECT
        # equals child's issuer DN. That needs an index by subject name, so we
        # build name buckets from raw DER cheaply using cached ParsedCert where
        # available, parsing only issuers reachable by name. To find issuers by
        # name without parsing all certificates, maintain a precomputed name
        # index (built during ingestion; see store detail). Fallback: parse all
        # when the index is absent (older stores).
        index = self._subject_name_index()
        graph._subject_index = index

        def candidate_issuers(child_fp: str) -> list[str]:
            child = graph.certs.get(child_fp) or self.cert(child_fp)
            if child is None:
                return []
            digests = index.get(child.issuer_der, [])
            out = []
            for d in digests:
                pc = graph._materialize(d)
                if pc is not None:
                    out.append(d)
            return sorted(out)

        graph.candidate_issuers = candidate_issuers  # type: ignore[assignment]

        # by_issuer used by revocation engine: resolve by name + AKI.
        def by_issuer(name_der, aki):
            res = []
            for d in index.get(name_der, []):
                pc = graph._materialize(d)
                if pc is None:
                    continue
                if aki is not None and pc.ski is not None and pc.ski != aki:
                    continue
                res.append(pc)
            return res

        graph.by_issuer = by_issuer  # type: ignore[assignment]
        return graph

    def _subject_name_index(self) -> dict[bytes, list[str]]:
        """Use the cheap index materialized at seal time (raw Name DER keys,
        base64 encoded in the sidecar file).

        The sidecar is a pure acceleration hint: its canonical bytes are
        anchored to the sealed manifest at seal time (``sidecar_anchors`` in
        the database row). A missing/truncated/corrupt/replaced sidecar — or a
        store sealed before anchors existed — is rebuilt from blobs (slow path
        for old stores only), so tampering can never hide a certificate."""
        cached = getattr(self, "_name_idx", None)
        if cached is not None:
            return cached
        idx_path = self._name_index_path()
        raw_index = self._read_anchored_sidecar(
            idx_path, "nameindex")
        idx: dict[bytes, list[str]] = {}
        if raw_index is not None:
            try:
                for name_b64, digests in raw_index.items():
                    idx[base64.b64decode(name_b64)] = digests
            except (ValueError, TypeError):
                # Illegal base64 inside an otherwise byte-valid sidecar:
                # rebuild rather than trust damaged rows.
                idx = {}
                raw_index = None
        if raw_index is None:
            # Slow path: stores sealed before sidecars/anchors existed, or a
            # damaged sidecar. Parse reachable issuers/all certs as required.
            for d in self.content["certificates"]:
                pc = self.cert(d)
                if pc is not None:
                    idx.setdefault(pc.subject_der, []).append(d)
            self._heal_name_sidecar(idx)
        for v in idx.values():
            v.sort()
        self._name_idx = idx
        return idx

    def _heal_name_sidecar(self, idx: dict[bytes, list[str]]) -> None:
        """Persist a freshly rebuilt name sidecar (and its anchor) so the next
        cold process is fast again. Never fatal on an unwritable volume."""
        try:
            name_index = {base64.b64encode(k).decode(): v
                          for k, v in idx.items()}
            data = canonical.dumps(name_index)
            self._write_sidecar(self._name_index_path(), data)
            self.store.anchor_sidecar(
                self.manifest["evidence_set_id"], "nameindex",
                hashlib.sha256(data).hexdigest())
        except Exception:
            pass

    def _name_index_path(self) -> str:
        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.nameindex.json")

    # --------------------------------------------------------- revocation
    def _ensure_revocation_index(self) -> None:
        if self._rev_index_loaded:
            return
        self._crl_received = {x["sha256"]: x["received_at"]
                              for x in self.content.get("crls", [])}
        self._ocsp_received = {x["sha256"]: x["received_at"]
                               for x in self.content.get("ocsps", [])}
        sidecar = self._load_rev_index_sidecar()
        if (sidecar is not None
                and self._sidecar_covers_universe(sidecar)
                and self._sidecar_rows_well_formed(sidecar)):
            try:
                self._apply_rev_sidecar(sidecar)
            except Exception:
                # Corrupt row content: drop sidecar-carried dispositions and
                # rebuild via the exact eager path (certificate parse problems
                # are unrelated and must be preserved).
                self._crl_by_issuer = {}
                self._ocsp_by_serial = {}
                self._crl_cache = {d: v for d, v in self._crl_cache.items()
                                   if d not in self._crl_received}
                self._ocsp_cache = {d: v for d, v in self._ocsp_cache.items()
                                    if d not in self._ocsp_received}
                self.parse_problems = [
                    p for p in self.parse_problems
                    if not ((p["kind"] == "crl"
                             and p["sha256"] in self._crl_received)
                            or (p["kind"] == "ocsp"
                                and p["sha256"] in self._ocsp_received))]
                self._build_rev_index_from_blobs()
        else:
            # Missing/stale/partial/tampered sidecar (stores sealed before
            # sidecars existed, a digest mismatch against the sealed anchor,
            # or the offline package review): exact eager parse, which
            # reproduces the original dispositions byte-for-byte.
            self._build_rev_index_from_blobs()
            self._heal_rev_sidecar()
        for v in self._crl_by_issuer.values():
            v.sort()
        for v in self._ocsp_by_serial.values():
            v.sort()
        self._rev_index_loaded = True

    def _apply_rev_sidecar(self, sidecar: dict) -> None:
        for row in sidecar.get("crls", []):
            digest = row["s"]
            if digest not in self._crl_received:
                continue
            if row.get("e"):
                # Seal-time full parse already rejected this object; carry
                # the verdict forward without touching the blob.
                self._record_rev_problem("crl", digest, row.get("p"))
                continue
            aki = base64.b64decode(row["a"]) if row.get("a") else None
            self._crl_by_issuer.setdefault(
                base64.b64decode(row["i"]), []).append((digest, aki))
        for row in sidecar.get("ocsps", []):
            digest = row["s"]
            if digest not in self._ocsp_received:
                continue
            if row.get("e"):
                self._record_rev_problem("ocsp", digest, row.get("p"))
                continue
            for serial in row["n"]:
                self._ocsp_by_serial.setdefault(serial, []).append(digest)

    def _sidecar_covers_universe(self, sidecar: dict) -> bool:
        """The sidecar must enumerate exactly the sealed CRL/OCSP universe;
        otherwise scope filtering could silently hide an object's disposition.
        Any mismatch forces the exact eager blob path."""
        try:
            side_crls = {r["s"] for r in sidecar.get("crls", [])}
            side_ocsps = {r["s"] for r in sidecar.get("ocsps", [])}
        except (TypeError, KeyError):
            return False
        return (side_crls == set(self._crl_received)
                and side_ocsps == set(self._ocsp_received))

    @staticmethod
    def _sidecar_rows_well_formed(sidecar: dict) -> bool:
        """Structural validation of every row before any scope value is
        trusted: valid-flag rows carry decodable base64 scope fields (CRL
        issuer Name/AKI, OCSP serial list), rejected rows carry the seal-time
        verdict. Anything odd (wrong types, duplicate rows, bad encodings)
        rejects the whole sidecar and routes through exact eager parsing."""
        try:
            crl_rows = sidecar["crls"]
            ocsp_rows = sidecar["ocsps"]
            if not isinstance(crl_rows, list) or not isinstance(ocsp_rows, list):
                return False
            seen_crls: set[str] = set()
            for row in crl_rows:
                if not isinstance(row, dict) or row.get("s") in seen_crls:
                    return False
                seen_crls.add(row["s"])
                if row.get("e"):
                    if not isinstance(row.get("p"), dict):
                        return False
                    continue
                if not isinstance(row.get("i"), str):
                    return False
                base64.b64decode(row["i"], validate=True)
                if row.get("a") is not None:
                    if not isinstance(row["a"], str):
                        return False
                    base64.b64decode(row["a"], validate=True)
            seen_ocsps: set[str] = set()
            for row in ocsp_rows:
                if not isinstance(row, dict) or row.get("s") in seen_ocsps:
                    return False
                seen_ocsps.add(row["s"])
                if row.get("e"):
                    if not isinstance(row.get("p"), dict):
                        return False
                    continue
                serials = row.get("n")
                if not isinstance(serials, list):
                    return False
                if any(not isinstance(n, int) or isinstance(n, bool)
                       or n < 0 for n in serials):
                    return False
                if len(set(serials)) != len(serials):
                    return False
        except (ValueError, TypeError, KeyError):
            return False
        return True

    def _read_anchored_sidecar(self, path: str, kind: str):
        """Read and JSON-parse a sidecar file only when its canonical bytes
        match the seal-time anchor recorded in the database manifest
        (``sidecar_anchors``). Returns the parsed object, or ``None`` when the
        file is absent/truncated/corrupt/replaced, when the store predates
        anchors, or when the backing store cannot provide an anchor.

        Anchoring covers *every* byte of the file — JSON syntax, version, all
        digests and all scope/verdict fields — so replacing any issuer/AKI/
        serial/verdict value with otherwise legal content is detected."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            return None
        anchors = self._sidecar_anchors()
        if anchors is None or kind not in anchors:
            # Store sealed before anchors existed: do not trust an unanchored
            # hint byte-for-byte; let the caller take its slow fallback.
            return None
        if hashlib.sha256(raw).hexdigest() != anchors[kind]:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _sidecar_anchors(self) -> dict | None:
        cached = getattr(self, "_sidecar_anchor_cache", "unset")
        if cached != "unset":
            return cached
        try:
            row = self.store.get_set(self.manifest["evidence_set_id"])
            anchors = json.loads(row["sidecar_anchors"]) \
                if row["sidecar_anchors"] else {}
        except Exception:
            return None
        if not isinstance(anchors, dict):
            anchors = None
        self._sidecar_anchor_cache = anchors
        return anchors

    @staticmethod
    def _write_sidecar(path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _heal_rev_sidecar(self) -> None:
        """After an exact eager rebuild (tampered/legacy sidecar), persist the
        freshly computed index and anchor it, so the next cold process is fast
        again. The rebuilt index derives solely from the sealed, content-
        addressed blobs and is therefore identical to the seal-time bytes."""
        try:
            rev_index, _entries = build_revocation_index(
                self.content.get("crls", []), self.content.get("ocsps", []),
                self.get_blob)
            data = canonical.dumps(rev_index)
            self._write_sidecar(self._rev_index_path(), data)
            self.store.anchor_sidecar(
                self.manifest["evidence_set_id"], "revindex",
                hashlib.sha256(data).hexdigest())
        except Exception:
            pass

    def _record_rev_problem(self, kind: str, digest: str,
                            problem: dict | None) -> None:
        if any(p["sha256"] == digest and p["kind"] == kind
               for p in self.parse_problems):
            (self._crl_cache if kind == "crl" else self._ocsp_cache)[digest] = None
            return
        problem = problem or {}
        self.parse_problems.append({
            "sha256": digest, "kind": kind,
            "code": problem.get("code", "MALFORMED_EVIDENCE"),
            "message": problem.get("message", ""),
            "detail": problem.get("detail", {})})
        # Mark cached as failed so on-demand access never re-reads the blob.
        (self._crl_cache if kind == "crl" else self._ocsp_cache)[digest] = None

    def _rev_index_path(self) -> str:
        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.revindex.json")

    def _load_rev_index_sidecar(self) -> dict | None:
        data = self._read_anchored_sidecar(self._rev_index_path(), "revindex")
        if data is None:
            return None
        if data.get("version") != REV_INDEX_VERSION:
            return None
        return data

    def _build_rev_index_from_blobs(self) -> None:
        """Fallback for stores sealed before revocation sidecars existed and
        for offline package review: fully parse every revocation object via
        the same on-demand path, exactly reproducing the eager loader's scope
        index and parse-rejection dispositions (these paths stay
        byte-identical). The sealed content lists are SHA-sorted, so the
        resulting parse-problem order is deterministic."""
        for digest in self._crl_received:
            obj = self.get_crl(digest)
            if obj is not None:
                self._crl_by_issuer.setdefault(obj.issuer_der, []).append(
                    (digest, obj.aki))
        for digest in self._ocsp_received:
            obj = self.get_ocsp(digest)
            if obj is not None:
                for serial in obj.responses:
                    self._ocsp_by_serial.setdefault(serial, []).append(digest)

    def get_crl(self, digest: str) -> ev.CrlObject | None:
        """Fully parse one CRL on demand; failures are recorded once."""
        if digest in self._crl_cache:
            return self._crl_cache[digest]
        try:
            raw = self.get_blob(digest)
            obj = ev.parse_crl(raw, self._crl_received[digest])
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._crl_cache[digest] = None
            self.parse_problems.append({
                "sha256": digest, "kind": "crl",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        except KeyError:
            self._crl_cache[digest] = None
            return None
        self._crl_cache[digest] = obj
        self.crls[digest] = obj
        _metrics.record_parsed(self.manifest["evidence_set_id"], "crl", digest)
        return obj

    def get_ocsp(self, digest: str) -> ev.OcspObject | None:
        """Fully parse one OCSP response on demand; failures recorded once."""
        if digest in self._ocsp_cache:
            return self._ocsp_cache[digest]
        try:
            raw = self.get_blob(digest)
            obj = ev.parse_ocsp(raw, self._ocsp_received[digest])
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._ocsp_cache[digest] = None
            self.parse_problems.append({
                "sha256": digest, "kind": "ocsp",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        except KeyError:
            self._ocsp_cache[digest] = None
            return None
        self._ocsp_cache[digest] = obj
        self.ocsps[digest] = obj
        _metrics.record_parsed(self.manifest["evidence_set_id"], "ocsp", digest)
        return obj

    def crl_candidates_for(self, cert: ParsedCert) -> list[ev.CrlObject]:
        """CRLs whose issuer Name/AKI can cover ``cert`` — the exact pre-filter
        the revocation engine applies before scope/signature/window checks."""
        self._ensure_revocation_index()
        out: list[ev.CrlObject] = []
        seen: set[str] = set()
        for digest, aki in self._crl_by_issuer.get(cert.issuer_der, []):
            if digest in seen:
                continue
            seen.add(digest)
            if aki is not None and cert.aki is not None and aki != cert.aki:
                continue
            obj = self.get_crl(digest)
            if obj is not None:
                out.append(obj)
        return out

    def ocsp_candidates_for(self, cert: ParsedCert) -> list[ev.OcspObject]:
        """OCSP responses carrying a single response for ``cert``'s serial."""
        self._ensure_revocation_index()
        out: list[ev.OcspObject] = []
        for digest in self._ocsp_by_serial.get(cert.serial, []):
            obj = self.get_ocsp(digest)
            if obj is not None:
                out.append(obj)
        return out

    def load_revocation(self) -> None:
        """Materialize the cheap scope index. Revocation objects themselves
        are parsed lazily through
        :meth:`crl_candidates_for`/`ocsp_candidates_for`."""
        self._ensure_revocation_index()
