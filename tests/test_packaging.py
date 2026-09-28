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


def test_declared_version_matches_the_installed_module():
    # __version__ is what `pcdlint --version` and SARIF print; pyproject is
    # what PyPI records. They are edited by hand in two places.
    from pcdlint import __version__

    assert __version__ == _pyproject()["project"]["version"]


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
