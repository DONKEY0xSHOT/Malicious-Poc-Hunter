"""Test that YARA rules fire on malicious fixtures and NOT on benign ones."""
import pytest
from pathlib import Path
from backend.scanner.yara_engine import YaraEngine

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def engine(rules_dir):
    return YaraEngine(rules_dir)


def triggered_rules(engine, filepath: str) -> set[str]:
    return {m.rule_name for m in engine.scan_file(filepath)}


# ---- True positives ---- #

def test_python_reverse_shell_detected(engine):
    rules = triggered_rules(engine, str(FIXTURES / "malicious_reverse_shell.py"))
    assert "Python_Reverse_Shell" in rules, f"Got: {rules}"


def test_obfuscation_exec_detected(engine):
    rules = triggered_rules(engine, str(FIXTURES / "malicious_obfuscated.py"))
    assert "Obfuscation_Encoded_Execution" in rules, f"Got: {rules}"


def test_rat_indicators_detected(engine):
    rules = triggered_rules(engine, str(FIXTURES / "malicious_rat.py"))
    assert "Python_RAT_Indicators" in rules, f"Got: {rules}"


def test_exfiltration_detected(engine):
    rules = triggered_rules(engine, str(FIXTURES / "malicious_exfil.py"))
    assert "Data_Exfiltration_Python" in rules, f"Got: {rules}"


def test_persistence_detected(engine):
    rules = triggered_rules(engine, str(FIXTURES / "malicious_persistence.sh"))
    assert "Linux_Persistence" in rules, f"Got: {rules}"


# ---- False positive prevention ---- #

def test_benign_b64_no_false_positive(engine):
    rules = triggered_rules(engine, str(FIXTURES / "benign_b64_usage.py"))
    assert "Obfuscation_Encoded_Execution" not in rules, (
        f"False positive! Triggered: {rules}"
    )


def test_benign_writeup_no_ransomware_false_positive(engine):
    """Markdown security writeup mentioning ransomware keywords should NOT trigger."""
    rules = triggered_rules(engine, str(FIXTURES / "benign_security_writeup.md"))
    assert "Ransomware" not in rules, (
        f"False positive on markdown doc! Triggered: {rules}"
    )


def test_get_rule_info_returns_all_rules(engine):
    """get_rule_info should not crash and return a list."""
    info = engine.get_rule_info()
    assert isinstance(info, list)
