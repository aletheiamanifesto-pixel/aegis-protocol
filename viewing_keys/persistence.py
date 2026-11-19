#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/persistence.py - Viewing keys and regulatory requests in the database.

The managers (ViewingKeyManagerV2, RegulatoryAccessManager) keep their logic unchanged:
their in-memory dicts are replaced with `DBMap`s backed by the `aegis_state` table,
and every public method saves the changes at the end (or discards them on error).
Records are encrypted at rest (Fernet), because they contain key secrets.

Usage (per request, with the API's DB session):

    vk = persistent_vk_manager(db)
    rm = persistent_regulatory_manager(db, vk)
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import time
import uuid
from collections.abc import MutableMapping
from dataclasses import asdict, fields
from typing import Any, Callable, Dict, Iterator, List

from cryptography.fernet import Fernet

import db_models
from viewing_keys.regulatory_flow import RegulatoryAccessManager, RegulatoryAccessRequest, RequestStatus
from viewing_keys.scope_filter import KeyScope, KeyStatus
from viewing_keys.viewing_keys_v2 import ViewingKeyManagerV2, ViewingKeyRecord


def _fernet() -> Fernet:
    """AEGIS_STATE_KEY (Fernet key) if set; otherwise derived from SECRET_KEY.
    WARNING: changing SECRET_KEY without AEGIS_STATE_KEY makes the saved records unreadable."""
    explicit = os.getenv("AEGIS_STATE_KEY", "").strip()
    if explicit:
        return Fernet(explicit.encode())
    from aegis_env import get_secret_key

    digest = hashlib.sha256(b"aegis-state-v1:" + get_secret_key().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


# ---------------------------------------------------------------------------
# Record (de)serialization
# ---------------------------------------------------------------------------

def _vk_to_json(r: ViewingKeyRecord) -> Dict[str, Any]:
    d = asdict(r)
    d["secret"] = r.secret.hex()
    d["scope"] = r.scope.value
    d["status"] = r.status.value
    return d


def _vk_from_json(d: Dict[str, Any]) -> ViewingKeyRecord:
    d = dict(d)
    d["secret"] = bytes.fromhex(d["secret"])
    d["scope"] = KeyScope(d["scope"])
    d["status"] = KeyStatus(d["status"])
    return ViewingKeyRecord(**d)


def _req_to_json(r: RegulatoryAccessRequest) -> Dict[str, Any]:
    d = asdict(r)
    d["scope_requested"] = r.scope_requested.value
    d["scope_granted"] = r.scope_granted.value if r.scope_granted else None
    d["status"] = r.status.value
    return d


def _req_from_json(d: Dict[str, Any]) -> RegulatoryAccessRequest:
    d = dict(d)
    d["scope_requested"] = KeyScope(d["scope_requested"])
    d["scope_granted"] = KeyScope(d["scope_granted"]) if d.get("scope_granted") else None
    d["status"] = RequestStatus(d["status"])
    known = {f.name for f in fields(RegulatoryAccessRequest)}
    return RegulatoryAccessRequest(**{k: v for k, v in d.items() if k in known})


_identity = (lambda x: x, lambda x: x)


# ---------------------------------------------------------------------------
# DB-backed mapping with a per-operation cache
# ---------------------------------------------------------------------------

class DBMap(MutableMapping):
    """Mapping on the `aegis_state` table (namespace, key) → encrypted JSON.

    Loaded objects stay in the cache until `flush()`, so changes made in
    place (record.use_count += 1) are saved too.
    """

    def __init__(self, db, namespace: str, codec=_identity):
        self.db, self.ns = db, namespace
        self.to_json, self.from_json = codec
        self.reset()

    def reset(self) -> None:
        self._cache: Dict[str, Any] = {}
        self._loaded: Dict[str, str] = {}  # key -> ciphertext-independent snapshot (JSON)
        self._deleted: set = set()

    def _row(self, key: str):
        return self.db.query(db_models.PersistentState).filter_by(namespace=self.ns, key=key).first()

    def _decode(self, row):
        return self.from_json(json.loads(_fernet().decrypt(row.value.encode())))

    def __getitem__(self, key: str):
        if key in self._deleted:
            raise KeyError(key)
        if key not in self._cache:
            row = self._row(key)
            if row is None:
                raise KeyError(key)
            obj = self._decode(row)
            self._cache[key] = obj
            self._loaded[key] = json.dumps(self.to_json(obj), sort_keys=True)
        return self._cache[key]

    def __setitem__(self, key: str, value) -> None:
        self._deleted.discard(key)
        self._cache[key] = value

    def __delitem__(self, key: str) -> None:
        if key not in self:
            raise KeyError(key)
        self._cache.pop(key, None)
        self._deleted.add(key)

    def _db_keys(self) -> List[str]:
        rows = self.db.query(db_models.PersistentState.key).filter_by(namespace=self.ns).all()
        return [r[0] for r in rows]

    def __iter__(self) -> Iterator[str]:
        keys = [k for k in self._db_keys() if k not in self._deleted]
        keys += [k for k in self._cache if k not in keys]
        return iter(sorted(keys))

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key) -> bool:
        if key in self._deleted:
            return False
        return key in self._cache or self._row(key) is not None

    def flush(self) -> None:
        f = _fernet()
        for key in self._deleted:
            self.db.query(db_models.PersistentState).filter_by(namespace=self.ns, key=key).delete()
        for key, obj in self._cache.items():
            plain = json.dumps(self.to_json(obj), sort_keys=True)
            if self._loaded.get(key) == plain:
                continue  # unchanged
            token = f.encrypt(plain.encode()).decode()
            row = self._row(key)
            if row is None:
                self.db.add(db_models.PersistentState(namespace=self.ns, key=key, value=token, updated_at=time.time()))
            else:
                row.value, row.updated_at = token, time.time()
        self.db.commit()
        self.reset()


class DBLog:
    """Append-only list (audit trail) on `aegis_state`, in insertion order."""

    def __init__(self, db, namespace: str):
        self.map = DBMap(db, namespace)

    def append(self, entry: Dict[str, Any]) -> None:
        self.map[f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}"] = entry

    def __iter__(self):
        return (self.map[k] for k in self.map)

    def reset(self) -> None:
        self.map.reset()

    def flush(self) -> None:
        self.map.flush()


def _transactional(obj, stores: List[Any]) -> None:
    """Wrap every public method: save at the end, discard on error (nested calls included)."""
    depth = {"n": 0}

    def wrap(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def inner(*a, **kw):
            if depth["n"] == 0:
                for s in stores:
                    s.reset()
            depth["n"] += 1
            try:
                out = fn(*a, **kw)
            except Exception:
                depth["n"] -= 1
                if depth["n"] == 0:
                    for s in stores:
                        s.reset()
                    obj_db = getattr(stores[0], "db", None) or stores[0].map.db
                    obj_db.rollback()
                raise
            depth["n"] -= 1
            if depth["n"] == 0:
                for s in stores:
                    s.flush()
            return out

        return inner

    for name in dir(type(obj)):
        if not name.startswith("_") and callable(getattr(obj, name)):
            setattr(obj, name, wrap(getattr(obj, name)))


def persistent_vk_manager(db) -> ViewingKeyManagerV2:
    mgr = ViewingKeyManagerV2()
    mgr._keys = DBMap(db, "vk2.keys", (_vk_to_json, _vk_from_json))
    mgr._master_keys = DBMap(db, "vk2.masters")
    mgr._audit_trail = DBLog(db, "vk2.audit")
    _transactional(mgr, [mgr._keys, mgr._master_keys, mgr._audit_trail])
    return mgr


def persistent_regulatory_manager(db, vk_manager: ViewingKeyManagerV2) -> RegulatoryAccessManager:
    rm = RegulatoryAccessManager(vk_manager)
    rm._requests = DBMap(db, "regulatory.requests", (_req_to_json, _req_from_json))
    _transactional(rm, [rm._requests])
    return rm
