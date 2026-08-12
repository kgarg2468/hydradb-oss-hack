"""Deterministic 63-bit ids.

HydraDB has no secondary property index, so every hot lookup has to enter the
graph through ``{id: ...}``. That makes the application the owner of the
name -> id mapping, and the mapping has to be *stable across runs and across
machines* or an incremental ingest would create a second copy of the graph.

Ids are therefore derived, not allocated: ``blake2b(namespaced_key)`` folded to
63 bits (positive in every signed-64 integer representation the wire format may
use). Because the mapping is a hash it can in principle collide, so every build
runs its keys through an :class:`IdRegistry`, which raises on the first pair of
distinct keys that land on the same id. At 63 bits a collision needs ~4e9 keys
for even a 50 % chance, but "impossible" and "unchecked" are different things
and this graph is append-only: a silent collision is unrecoverable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# 63 bits: fits a signed 64-bit integer without ever going negative.
ID_BITS = 63
ID_MASK = (1 << ID_BITS) - 1

# Namespaces. Never reuse or renumber these — the ids they produce are durable.
NS_REPO = "repo"
NS_PACKAGE = "pkg"
NS_VERSION = "pv"
NS_MAINTAINER = "maint"
NS_WATERMARK = "wm"
NS_EDGE = "edge"


class IdCollision(Exception):
    """Two distinct keys hashed to the same id."""


def stable_id(key: str) -> int:
    """A deterministic 63-bit id for an already-namespaced key."""
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") & ID_MASK


def repo_key(slug: str) -> str:
    return f"{NS_REPO}:{slug}"


def package_key(name: str) -> str:
    return f"{NS_PACKAGE}:{name}"


def version_key(name: str, version: str) -> str:
    return f"{NS_VERSION}:{name}@{version}"


def maintainer_key(name: str) -> str:
    return f"{NS_MAINTAINER}:{name}"


def watermark_key(slug: str) -> str:
    return f"{NS_WATERMARK}:{slug}"


def edge_key(rel_type: str, src: int, dst: int, valid_from: int = 0) -> str:
    """Key for an interval edge.

    ``valid_from`` is part of the identity because the same (repo, version) pair
    can be resolved, dropped and resolved again; each of those is a separate
    fact with its own interval. ``valid_to`` deliberately is *not* part of the
    identity — an interval that is still open today and closes tomorrow is the
    same fact, learned more completely, and must update in place rather than
    turn into a second edge.
    """
    return f"{NS_EDGE}:{rel_type}:{src}:{dst}:{valid_from}"


def repo_id(slug: str) -> int:
    return stable_id(repo_key(slug))


def package_id(name: str) -> int:
    return stable_id(package_key(name))


def version_id(name: str, version: str) -> int:
    return stable_id(version_key(name, version))


def maintainer_id(name: str) -> int:
    return stable_id(maintainer_key(name))


def watermark_id(slug: str) -> int:
    return stable_id(watermark_key(slug))


def edge_id(rel_type: str, src: int, dst: int, valid_from: int = 0) -> int:
    return stable_id(edge_key(rel_type, src, dst, valid_from))


@dataclass
class IdRegistry:
    """Mints ids and refuses to hand the same one to two different keys."""

    _by_id: dict[int, str] = field(default_factory=dict)

    def mint(self, key: str) -> int:
        ident = stable_id(key)
        seen = self._by_id.get(ident)
        if seen is None:
            self._by_id[ident] = key
            return ident
        if seen != key:
            raise IdCollision(
                f"id {ident} is claimed by both {seen!r} and {key!r}; "
                "the id space is append-only, so this must be resolved before ingest"
            )
        return ident

    def repo(self, slug: str) -> int:
        return self.mint(repo_key(slug))

    def package(self, name: str) -> int:
        return self.mint(package_key(name))

    def version(self, name: str, version: str) -> int:
        return self.mint(version_key(name, version))

    def maintainer(self, name: str) -> int:
        return self.mint(maintainer_key(name))

    def edge(self, rel_type: str, src: int, dst: int, valid_from: int = 0) -> int:
        return self.mint(edge_key(rel_type, src, dst, valid_from))

    def __len__(self) -> int:
        return len(self._by_id)

    @property
    def keys(self) -> dict[int, str]:
        return dict(self._by_id)
