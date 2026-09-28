"""Packaging invariants that only fail at release time.

Nothing here exercises runtime behaviour: these assert that the metadata a
build backend reads agrees with the code that ships, because the two are
edited in different files and drift silently until someone publishes.
"""

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no tomllib; tomli is its backport (a dev extra).
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_version_lives_in_exactly_one_place():
    """The version is written once, in ``pcdlint.__version__``.

    ``__version__`` is what ``pcdlint --version`` and SARIF print; the wheel
    metadata is what PyPI records. Keeping a literal in both meant editing
    two files in lockstep, and they drifted, so pyproject now derives its
    version instead of carrying a copy.
    """
    from pcdlint import __version__

    project = _pyproject()["project"]
    assert "version" not in project, (
        "project.version is static -- it would drift from pcdlint.__version__"
    )
    assert "version" in project.get("dynamic", []), (
        "project.version must be declared dynamic"
    )
    assert (_pyproject()["tool"]["setuptools"]["dynamic"]["version"]["attr"]
            == "pcdlint.__version__")
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__


def test_installed_metadata_agrees_with_the_module():
    """The dynamic version really is what setuptools resolved at install."""
    from importlib.metadata import version

    from pcdlint import __version__

    assert version("pcdlint") == __version__, (
        f"installed metadata says {version('pcdlint')!r} but "
        f"pcdlint.__version__ says {__version__!r} -- reinstall with "
        "`pip install -e .` after changing the version"
    )


def test_console_scripts_point_at_real_entry_points():
    from pcdlint.cli import main

    for name, target in _pyproject()["project"]["scripts"].items():
        module, _, attribute = target.partition(":")
        assert module and attribute, f"{name} = {target!r} is not module:attr"
        imported = __import__(module, fromlist=[attribute])
        assert getattr(imported, attribute, None) is main, (
            f"{name} -> {target} does not resolve to pcdlint.cli:main"
        )


def test_build_backend_floor_covers_the_declared_license_form():
    """PEP 639 SPDX license strings need setuptools >= 77.

    ``license = "MIT"`` is rejected by older setuptools (which only accepts
    ``{file=}`` / ``{text=}``), so a floor below 77 turns into a build that
    fails for anyone whose resolver pins an older version.
    """
    project = _pyproject()["project"]
    license_form = project.get("license")

    requires = _pyproject()["build-system"]["requires"]
    floors = []
    for requirement in requires:
        match = re.match(r"setuptools\s*(>=|~=|==)\s*([0-9][0-9.]*)", requirement)
        if match:
            floors.append(tuple(int(p) for p in match.group(2).split(".")))
    assert floors, "build-system.requires does not pin setuptools"

    if isinstance(license_form, str):
        # An SPDX expression: PEP 639 support landed in setuptools 77.0.3.
        assert max(floors) >= (77, 0, 3), (
            f"license = {license_form!r} is a PEP 639 expression but "
            f"setuptools floor {max(floors)} predates support for it"
        )
    elif isinstance(license_form, dict):
        # Legacy table form: every setuptools that reads PEP 621 accepts it.
        assert set(license_form) & {"file", "text"}, (
            f"license = {license_form!r} must use 'file' or 'text'"
        )
