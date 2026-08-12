"""Id determinism and collision detection.

The graph is append-only and has no secondary index, so ids *are* the schema:
if the same logical fact ever minted two different ids the store would silently
grow a second copy of itself, and there would be no way to delete either.
"""

import pytest

from hindsight.ids import (
    ID_MASK,
    IdCollision,
    IdRegistry,
    edge_id,
    edge_key,
    maintainer_id,
    package_id,
    repo_id,
    stable_id,
    version_id,
    watermark_id,
)


def test_ids_are_deterministic_across_calls():
    assert repo_id("acme/web") == repo_id("acme/web")
    assert version_id("chalk", "5.3.0") == version_id("chalk", "5.3.0")
    assert edge_id("HS_RESOLVES", 1, 2, 300) == edge_id("HS_RESOLVES", 1, 2, 300)


def test_ids_are_pinned_values():
    # Frozen so an accidental change to the hashing scheme fails loudly rather
    # than orphaning every node already written to a durable store.
    assert stable_id("repo:acme/web") == repo_id("acme/web")
    assert repo_id("acme/web") == 8712617856422249063
    assert package_id("chalk") == 471252229458468517
    assert version_id("chalk", "5.3.0") == 4853305677416239379
    assert maintainer_id("qix") == 3030640243919545617
    assert watermark_id("acme/web") == 5172092400295288025
    assert edge_id("HS_RESOLVES", 1, 2, 300) == 56148044554492778


def test_ids_fit_63_bits_and_stay_positive():
    for key in ("repo:a", "pkg:@scope/name", "pv:x@0.0.0", "maint:someone", "edge:R:1:2:3"):
        value = stable_id(key)
        assert 0 <= value <= ID_MASK
        assert value < 2**63


def test_namespaces_keep_identical_names_apart():
    assert repo_id("chalk") != package_id("chalk") != maintainer_id("chalk")
    assert package_id("chalk") != maintainer_id("chalk")


def test_version_id_is_not_confused_by_scoped_names():
    # "@scope/a" @ "1.0.0" and "@scope" @ "a@1.0.0" must not share an id.
    assert version_id("@scope/a", "1.0.0") != version_id("@scope", "a@1.0.0")


def test_edge_identity_ignores_valid_to_but_not_valid_from():
    # An interval that closes later is the same fact, learned more completely.
    assert edge_id("R", 1, 2, 100) == edge_id("R", 1, 2, 100)
    # A dependency dropped and re-added is a different fact.
    assert edge_id("R", 1, 2, 100) != edge_id("R", 1, 2, 200)
    assert "valid_to" not in edge_key("R", 1, 2, 100)


def test_registry_returns_the_same_id_for_a_repeated_key():
    reg = IdRegistry()
    assert reg.package("chalk") == reg.package("chalk")
    assert len(reg) == 1


def test_registry_raises_on_a_real_collision():
    reg = IdRegistry()
    first = reg.package("chalk")
    # Force the collision the birthday bound makes untestable by construction.
    reg._by_id[stable_id("pkg:debug")] = "pkg:planted-imposter"
    with pytest.raises(IdCollision) as exc:
        reg.package("debug")
    assert "pkg:debug" in str(exc.value)
    assert "pkg:planted-imposter" in str(exc.value)
    assert first in reg.keys


def test_registry_tracks_every_namespace():
    reg = IdRegistry()
    reg.repo("acme/web")
    reg.package("chalk")
    reg.version("chalk", "5.3.0")
    reg.maintainer("qix")
    reg.edge("HS_RESOLVES", 1, 2, 3)
    assert len(reg) == 5
