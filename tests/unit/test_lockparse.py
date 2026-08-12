import json

from lockparse import parse_package_lock, split_spec


def test_split_spec_plain():
    assert split_spec("chalk@^5.0.0") == ("chalk", "^5.0.0")


def test_split_spec_scoped():
    assert split_spec("@babel/core@7.24.0") == ("@babel/core", "7.24.0")


def test_package_lock_v3_resolves_transitive_closure():
    lock = {
        "name": "fixture-app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture-app", "version": "1.0.0"},
            "node_modules/chalk": {
                "version": "5.3.0",
                "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
            },
            "node_modules/debug": {
                "version": "4.3.6",
                "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.6.tgz",
            },
            "node_modules/debug/node_modules/ms": {
                "version": "2.1.2",
                "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.2.tgz",
            },
            "node_modules/@scope/pkg": {
                "version": "1.2.3",
                "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz",
            },
        },
    }
    got = parse_package_lock(json.dumps(lock))
    assert got == {
        ("chalk", "5.3.0"),
        ("debug", "4.3.6"),
        ("ms", "2.1.2"),
        ("@scope/pkg", "1.2.3"),
    }


def test_package_lock_skips_workspace_links_and_file_resolutions():
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"version": "0.0.0"},
            "packages/internal-lib": {"version": "1.0.0"},
            "node_modules/internal-lib": {"version": "1.0.0", "link": True},
            "node_modules/local-dep": {"version": "2.0.0", "resolved": "file:../local-dep"},
            "node_modules/real-dep": {
                "version": "3.1.4",
                "resolved": "https://registry.npmjs.org/real-dep/-/real-dep-3.1.4.tgz",
            },
        },
    }
    got = parse_package_lock(json.dumps(lock))
    assert got == {("real-dep", "3.1.4")}
