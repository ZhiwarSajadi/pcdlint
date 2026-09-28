"""Discovery of ``[tool.pcdlint]`` configuration from pyproject.toml.

Config is located by walking up from each analyzed file to the nearest
``pyproject.toml`` that declares ``[tool.pcdlint]``, so a monorepo can give
every package its own rule set.

A broken or surprising config is an error (exit 2), never a silent fallback
to defaults: ``select = ["PCL999"]`` must not make the run look clean.
"""

import sys
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from pcdlint.rules import KNOWN_RULE_IDS

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no tomllib; tomli is its backport.
    import tomli as tomllib

_SECTION = "tool.pcdlint"
_KEYS = frozenset({"select", "ignore", "exclude"})


class ConfigError(Exception):
    """A configuration file exists but cannot be honored."""


@dataclass(frozen=True)
class Config:
    """Rule selection as declared by the nearest config file."""

    # None means "every rule"; a frozenset is an allowlist.
    select: frozenset | None = None
    ignore: frozenset = field(default_factory=frozenset)
    # Globs for files this project does not want scanned at all.
    exclude: frozenset = field(default_factory=frozenset)


DEFAULT = Config()


def selected(rule_id: str, select: frozenset | None, ignore: frozenset) -> bool:
    """Apply allowlist-then-denylist semantics to one rule id."""
    if select is not None and rule_id not in select:
        return False
    return rule_id not in ignore


def _rule_ids(value: object, key: str, path: Path, *,
              allow_empty: bool = False) -> frozenset:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(
            f"{_SECTION} {key} in {path} must be a list of rule ids, got {value!r}"
        )
    ids = frozenset(v.strip().upper() for v in value)
    # An empty allowlist switches every rule off, which looks exactly like a
    # clean run. That is the failure exit 2 exists to prevent, so a select
    # naming nothing is an error; an empty ignore just means "ignore nothing".
    if not ids and not allow_empty:
        raise ConfigError(
            f"{_SECTION} {key} in {path} must name at least one rule"
        )
    unknown = sorted(ids - KNOWN_RULE_IDS)
    if unknown:
        raise ConfigError(
            f"{_SECTION} {key} in {path} names unknown rule id(s): "
            f"{', '.join(unknown)} (known: {', '.join(sorted(KNOWN_RULE_IDS))})"
        )
    return ids


def _globs(value: object, key: str, path: Path) -> frozenset:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(
            f"{_SECTION} {key} in {path} must be a list of globs, got {value!r}"
        )
    # Empty entries would match nothing useful and are a typo, so they go.
    return frozenset(pattern for pattern in value if pattern.strip())


def _load(path: Path) -> tuple[Config | None, bool]:
    """Parse one pyproject.toml; ``(config, found)`` with found=False when it
    declares no [tool.pcdlint] section."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc

    tool = data.get("tool")
    if not isinstance(tool, dict) or "pcdlint" not in tool:
        return None, False

    section = tool["pcdlint"]
    if not isinstance(section, dict):
        raise ConfigError(f"{_SECTION} in {path} must be a table")

    unknown = sorted(str(k) for k in set(section) - _KEYS)
    if unknown:
        raise ConfigError(
            f"unknown key(s) in [{_SECTION}] ({path}): {', '.join(unknown)}; "
            f"expected select and ignore"
        )

    select = _rule_ids(section["select"], "select", path) if "select" in section else None
    ignore = (_rule_ids(section["ignore"], "ignore", path, allow_empty=True)
              if "ignore" in section else frozenset())
    exclude = (_globs(section["exclude"], "exclude", path)
               if "exclude" in section else frozenset())
    return Config(select=select, ignore=ignore, exclude=exclude), True


@cache
def _discover(start: Path) -> Config:
    """Config governing every file in ``start``, cached per directory.

    The walk is identical for every file sharing a directory, and parsing the
    same pyproject.toml once per file dominated large runs. A ConfigError is
    not cached -- only returns are -- so a broken config still raises on every
    call rather than turning into a clean run the second time.
    """
    for directory in [start, *start.parents]:
        candidate = directory / "pyproject.toml"
        if not candidate.is_file():
            continue
        config, found = _load(candidate)
        if found:
            return config or DEFAULT
    return DEFAULT


def load_for(file_path: str) -> Config:
    """Config governing ``file_path``; DEFAULT when nothing declares one."""
    if not file_path:
        return DEFAULT
    try:
        start = Path(file_path).resolve().parent
    except OSError:  # pragma: no cover - unresolvable paths are rare
        return DEFAULT
    return _discover(start)


def parse_rule_list(values: list[str] | None, flag: str, *,
                    allow_empty: bool = False) -> frozenset:
    """Turn repeated ``--select/--ignore`` arguments into a validated set."""
    ids: set[str] = set()
    for value in values or []:
        ids.update(part.strip().upper() for part in value.split(",") if part.strip())
    # ``--select ","`` and ``--select ""`` are an empty allowlist, which would
    # run no rules at all and report a clean run. Same reasoning as _rule_ids.
    if not ids and not allow_empty:
        raise ConfigError(f"{flag} must name at least one rule")
    unknown = sorted(ids - KNOWN_RULE_IDS)
    if unknown:
        raise ConfigError(
            f"unknown rule id(s) for {flag}: {', '.join(unknown)} "
            f"(known: {', '.join(sorted(KNOWN_RULE_IDS))})"
        )
    return frozenset(ids)
