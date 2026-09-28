"""Unit tests verifying the pclint alias package and entry points."""

import sys
from pathlib import Path


def test_pclint_package_exports() -> None:
    """pclint top-level package exports all expected public symbols."""
    import pclint

    assert hasattr(pclint, "__version__")
    assert hasattr(pclint, "Diagnostic")
    assert hasattr(pclint, "TaintOrigin")
    assert hasattr(pclint, "TaintTracker")
    assert hasattr(pclint, "RuleEngine")
    assert hasattr(pclint, "analyze_code")
    assert hasattr(pclint, "analyze_path")
    assert hasattr(pclint, "main")


def test_pclint_analyzer_alias() -> None:
    """pclint.analyzer provides working analyze_code and analyze_path."""
    from pclint.analyzer import analyze_code, analyze_path

    diags = analyze_code("x = 1")
    assert diags == []

    good_path = Path("examples/demo_good.py")
    if good_path.exists():
        assert analyze_path(good_path) == []


def test_pclint_cli_alias() -> None:
    """pclint.cli.main executes and handles check command."""
    from pclint.cli import main

    old_argv = sys.argv
    try:
        sys.argv = ["pclint", "check", "examples/demo_good.py"]
        exit_code = main()
        assert exit_code == 0
    finally:
        sys.argv = old_argv


def test_pclint_models_alias() -> None:
    """pclint.models re-exports Diagnostic and TaintOrigin correctly."""
    from pclint.models import Diagnostic, TaintOrigin

    origin = TaintOrigin(variable_name="t", source_call="time.time", lineno=1)
    diag = Diagnostic(
        file_path="foo.py",
        lineno=1,
        col_offset=0,
        rule_id="PCL001",
        rule_name="prefix-taint-injection",
        message="test",
        fix_suggestion="fix",
        severity="ERROR",
    )
    assert origin.source_call == "time.time"
    assert diag.rule_id == "PCL001"


def test_pclint_rules_and_taint_alias() -> None:
    """pclint.rules and pclint.taint re-export RuleEngine and TaintTracker."""
    import pclint.rules
    import pclint.taint

    assert hasattr(pclint.rules, "RuleEngine")
    assert hasattr(pclint.taint, "TaintTracker")
    tracker = pclint.taint.TaintTracker()
    engine = pclint.rules.RuleEngine(tracker)
    assert engine.tracker is tracker


def test_python_dash_m_pclint_module() -> None:
    """``python -m pclint`` runs like ``python -m pcdlint``."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "pclint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "pcdlint" in result.stdout


def test_taint_origin_records_variable_name() -> None:
    """TaintOrigin.variable_name names the bound variable instead of staying empty."""
    import ast

    from pcdlint.taint import TaintTracker

    tree = ast.parse('from datetime import datetime\nts = datetime.now()\n')
    tracker = TaintTracker()
    tracker.build_scopes(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            tracker.track_assignment(node)

    origin = tracker.tainted_vars["ts"]
    assert origin.source_call == "datetime.now"
    assert origin.variable_name == "ts"



def test_pclint_alias_warns_it_is_deprecated() -> None:
    """The top-level name can clash with any other distribution shipping it.

    The console script keeps working: it maps to pcdlint.cli:main and does
    not squat on an import name.
    """
    import subprocess

    result = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning",
         "-c", "import pclint"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, (
        "importing pclint must raise DeprecationWarning when escalated"
    )
    assert "deprecated" in result.stderr, result.stderr
    assert "removed in 1.0" in result.stderr, result.stderr
