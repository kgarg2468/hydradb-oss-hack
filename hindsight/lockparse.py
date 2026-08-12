"""Lockfile parsers: npm package-lock v1/v2/v3, yarn classic (v1), yarn berry (v2+).

Every parser returns a set of (package_name, version) pairs representing the
full resolved transitive closure recorded in the lockfile. The closure is the
point: a repo is exposed through packages its manifest never names.

Copied verbatim from poc/lockparse.py, which is validated against 5,028 real
lockfile snapshots from eight OSS repos.
"""

import json
import re

_RESOLUTION_RE = re.compile(r'^resolution:\s*"(.+)"\s*$')
_BERRY_VERSION_RE = re.compile(r'^version:\s*"?([^"\s]+)"?\s*$')
_CLASSIC_VERSION_RE = re.compile(r'^version\s+"?([^"\s]+)"?\s*$')

# Resolution protocols that do not denote a real npm registry release.
_NON_REGISTRY = ("@workspace:", "@link:", "@portal:", "@file:", "@exec:")


def split_spec(spec):
    """Split 'name@range' into (name, range), handling @scope/name."""
    spec = spec.strip().strip('"').strip("'")
    if not spec:
        return None, None
    if spec.startswith("@"):
        idx = spec.find("@", 1)
    else:
        idx = spec.find("@")
    if idx <= 0:
        return spec, None
    return spec[:idx], spec[idx + 1 :]


def parse_package_lock(text):
    """npm package-lock.json v1, v2 and v3."""
    data = json.loads(text)
    out = set()

    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if key == "":
                continue  # the root project itself
            version = meta.get("version")
            if not version or not isinstance(version, str):
                continue
            if meta.get("link") is True:
                continue  # workspace symlink, not a registry release
            # "node_modules/a/node_modules/b" -> "b"; keeps @scope/name intact.
            marker = "node_modules/"
            pos = key.rfind(marker)
            if pos == -1:
                continue  # a workspace entry such as "packages/foo"
            name = key[pos + len(marker) :]
            if not name:
                continue
            resolved = meta.get("resolved")
            if isinstance(resolved, str) and resolved.startswith("file:"):
                continue
            out.add((name, version))
        if out:
            return out

    # v1 fallback: recursive "dependencies" tree.
    def walk(node):
        deps = node.get("dependencies")
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and version and not version.startswith("file:"):
                out.add((name, version))
            walk(meta)

    walk(data)
    return out


def parse_yarn_lock(text):
    """yarn.lock, both classic (v1) and berry (v2+) syntax."""
    out = set()
    header = None
    version = None
    resolution = None

    def flush():
        if not header or header.startswith("__metadata"):
            return
        if resolution is not None:
            if any(p in resolution for p in _NON_REGISTRY):
                return
            name, rest = split_spec(resolution)
            ver = version
            if ver is None and rest and rest.startswith("npm:"):
                ver = rest[4:]
            if name and ver:
                out.add((name, ver))
            return
        if version is None:
            return
        first = header.split(",")[0]
        name, _ = split_spec(first)
        if name and not name.startswith("__"):
            out.add((name, version))

    for line in text.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            flush()
            header = line.rstrip().rstrip(":").strip()
            version = None
            resolution = None
            continue
        stripped = line.strip()
        m = _RESOLUTION_RE.match(stripped)
        if m:
            resolution = m.group(1)
            continue
        m = _BERRY_VERSION_RE.match(stripped) or _CLASSIC_VERSION_RE.match(stripped)
        if m:
            version = m.group(1)

    flush()
    return out


def parse_lockfile(path, text):
    if path.endswith("package-lock.json"):
        return parse_package_lock(text)
    if path.endswith("yarn.lock"):
        return parse_yarn_lock(text)
    raise ValueError("unsupported lockfile: %s" % path)
