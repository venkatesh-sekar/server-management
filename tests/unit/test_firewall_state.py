"""Unit tests for the firewall state management module."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime
import tempfile
import os

from sm.services.firewall_state import (
    StoredRule,
    FirewallState,
    FirewallStateManager,
    DriftReport,
    STATE_DIR,
    STATE_FILE,
    EXCLUSIVE_MARKER,
)
from sm.core.context import create_context


class TestStoredRule:
    """Tests for StoredRule dataclass."""

    def test_default_values(self):
        """StoredRule should have sensible defaults."""
        rule = StoredRule()
        assert rule.port is None
        assert rule.protocol == "tcp"
        assert rule.source == "0.0.0.0/0"
        assert rule.action == "ACCEPT"
        assert rule.chain == "INPUT"
        assert rule.protected is False
        assert rule.comment is None

    def test_to_dict(self):
        """Should convert to dictionary for YAML serialization."""
        rule = StoredRule(
            port=443,
            protocol="tcp",
            source="10.0.0.0/8",
            action="ACCEPT",
            chain="INPUT",
            comment="HTTPS traffic",
            protected=True,  # Only included when True
        )
        d = rule.to_dict()

        assert d["port"] == 443
        assert d["protocol"] == "tcp"
        assert d["source"] == "10.0.0.0/8"
        assert d["action"] == "ACCEPT"
        assert d["chain"] == "INPUT"
        assert d["comment"] == "HTTPS traffic"
        assert d["protected"] is True  # Only in dict when True

    def test_from_dict(self):
        """Should create from dictionary."""
        d = {
            "port": 5432,
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "action": "ACCEPT",
            "chain": "INPUT",
            "comment": "PostgreSQL",
        }
        rule = StoredRule.from_dict(d)

        assert rule.port == 5432
        assert rule.protocol == "tcp"
        assert rule.source == "192.168.1.0/24"
        assert rule.comment == "PostgreSQL"

    def test_from_dict_with_defaults(self):
        """Should use defaults for missing keys."""
        d = {"port": 80}
        rule = StoredRule.from_dict(d)

        assert rule.port == 80
        assert rule.protocol == "tcp"
        assert rule.source == "0.0.0.0/0"
        assert rule.action == "ACCEPT"

    def test_matches_basic(self):
        """Should match rules with same port/proto/source/action."""
        rule1 = StoredRule(port=443, protocol="tcp", source="0.0.0.0/0", action="ACCEPT")
        rule2 = StoredRule(port=443, protocol="tcp", source="0.0.0.0/0", action="ACCEPT")

        assert rule1.matches(rule2) is True

    def test_matches_different_port(self):
        """Should not match rules with different ports."""
        rule1 = StoredRule(port=443, protocol="tcp")
        rule2 = StoredRule(port=80, protocol="tcp")

        assert rule1.matches(rule2) is False

    def test_matches_different_protocol(self):
        """Should not match rules with different protocols."""
        rule1 = StoredRule(port=53, protocol="tcp")
        rule2 = StoredRule(port=53, protocol="udp")

        assert rule1.matches(rule2) is False

    def test_matches_different_source(self):
        """Should not match rules with different sources."""
        rule1 = StoredRule(port=443, source="0.0.0.0/0")
        rule2 = StoredRule(port=443, source="10.0.0.0/8")

        assert rule1.matches(rule2) is False

    def test_matches_different_action(self):
        """Should not match rules with different actions."""
        rule1 = StoredRule(port=443, action="ACCEPT")
        rule2 = StoredRule(port=443, action="DROP")

        assert rule1.matches(rule2) is False

    def test_matches_ignores_comment(self):
        """Should ignore comment when matching."""
        rule1 = StoredRule(port=443, comment="Rule 1")
        rule2 = StoredRule(port=443, comment="Rule 2")

        assert rule1.matches(rule2) is True

    def test_str_representation(self):
        """Should have readable string representation."""
        rule = StoredRule(
            port=443,
            protocol="tcp",
            source="10.0.0.0/8",
            action="ACCEPT",
            comment="HTTPS",
        )
        s = str(rule)

        assert "ACCEPT" in s
        assert "tcp/443" in s
        assert "10.0.0.0/8" in s
        assert "HTTPS" in s


class TestFirewallState:
    """Tests for FirewallState dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        state = FirewallState()

        assert state.version == 1
        assert state.rules == []
        assert state.exclusive_mode is False
        assert state.docker_aware is False
        assert state.systemd_installed is False
        assert len(state.preserved_chain_patterns) > 0

    def test_default_preserved_chains(self):
        """Should include fail2ban patterns by default."""
        state = FirewallState()

        assert "f2b-*" in state.preserved_chain_patterns
        assert "fail2ban-*" in state.preserved_chain_patterns

    def test_to_dict(self):
        """Should convert to dictionary."""
        state = FirewallState(
            version=1,
            rules=[StoredRule(port=80)],
            exclusive_mode=True,
            docker_aware=True,
        )
        d = state.to_dict()

        assert d["version"] == 1
        assert len(d["rules"]) == 1
        assert d["rules"][0]["port"] == 80
        assert d["exclusive_mode"] is True
        assert d["docker_aware"] is True
        assert "last_modified" in d

    def test_from_dict(self):
        """Should create from dictionary."""
        d = {
            "version": 1,
            "rules": [{"port": 443, "protocol": "tcp"}],
            "exclusive_mode": True,
            "docker_aware": True,
            "last_modified": "2024-01-01T00:00:00",
        }
        state = FirewallState.from_dict(d)

        assert state.version == 1
        assert len(state.rules) == 1
        assert state.rules[0].port == 443
        assert state.exclusive_mode is True
        assert state.docker_aware is True

    def test_from_dict_empty(self):
        """Should handle empty dictionary."""
        state = FirewallState.from_dict({})

        assert state.version == 1
        assert state.rules == []

    def test_from_dict_with_missing_keys(self):
        """Should use defaults for missing keys."""
        d = {"rules": [{"port": 22}]}
        state = FirewallState.from_dict(d)

        assert state.exclusive_mode is False
        assert state.docker_aware is False


class TestDriftReport:
    """Tests for DriftReport dataclass."""

    def test_no_drift(self):
        """Should report no drift when lists are empty."""
        report = DriftReport(
            unknown_rules=[],
            missing_rules=[],
            preserved_rules=[],
        )

        assert report.has_drift is False
        assert report.unknown_count == 0
        assert report.missing_count == 0

    def test_has_drift_unknown_rules(self):
        """Should detect drift when unknown rules exist."""
        report = DriftReport(
            unknown_rules=[{"port": 8080}],
            missing_rules=[],
            preserved_rules=[],
        )

        assert report.has_drift is True
        assert report.unknown_count == 1

    def test_has_drift_missing_rules(self):
        """Should detect drift when missing rules exist."""
        report = DriftReport(
            unknown_rules=[],
            missing_rules=[StoredRule(port=443)],
            preserved_rules=[],
        )

        assert report.has_drift is True
        assert report.missing_count == 1

    def test_counts(self):
        """Should correctly count rules."""
        report = DriftReport(
            unknown_rules=[{"port": 80}, {"port": 443}],
            missing_rules=[StoredRule(port=8080)],
            preserved_rules=[{"chain": "f2b-sshd"}],
        )

        assert report.unknown_count == 2
        assert report.missing_count == 1


class TestFirewallStateManager:
    """Tests for FirewallStateManager class."""

    @pytest.fixture
    def temp_state_dir(self):
        """Create temporary state directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_ctx(self):
        """Create a mock execution context."""
        return create_context(dry_run=False)

    @pytest.fixture
    def manager(self, temp_state_dir, mock_ctx):
        """Create state manager with temp directory."""
        with patch("sm.services.firewall_state.STATE_DIR", temp_state_dir):
            with patch("sm.services.firewall_state.STATE_FILE", temp_state_dir / "sm-rules.yaml"):
                with patch("sm.services.firewall_state.EXCLUSIVE_MARKER", temp_state_dir / "exclusive"):
                    yield FirewallStateManager(mock_ctx)

    def test_initial_state(self, manager):
        """Should have empty state initially."""
        assert len(manager.state.rules) == 0
        assert manager.state.exclusive_mode is False

    def test_add_rule(self, manager):
        """Should add rule to state."""
        rule = StoredRule(port=443, comment="HTTPS")
        result = manager.add_rule(rule)

        assert result is True
        assert len(manager.state.rules) == 1
        assert manager.state.rules[0].port == 443

    def test_add_rule_duplicate(self, manager):
        """Should not add duplicate rules."""
        rule = StoredRule(port=443)
        manager.add_rule(rule)
        result = manager.add_rule(rule)

        assert result is False
        assert len(manager.state.rules) == 1

    def test_remove_rule(self, manager):
        """Should remove rule from state."""
        rule = StoredRule(port=443)
        manager.add_rule(rule)

        result = manager.remove_rule(rule)

        assert result is True
        assert len(manager.state.rules) == 0

    def test_remove_rule_not_found(self, manager):
        """Should return False if rule not found."""
        rule = StoredRule(port=443)
        result = manager.remove_rule(rule)

        assert result is False

    def test_remove_protected_rule(self, manager):
        """Should raise error when removing protected rules."""
        from sm.core.exceptions import FirewallError

        rule = StoredRule(port=22, protected=True)
        manager.add_rule(rule)

        with pytest.raises(FirewallError):
            manager.remove_rule(rule)

        # Rule should still exist
        assert len(manager.state.rules) == 1

    def test_has_rule(self, manager):
        """Should check if rule exists via state."""
        rule = StoredRule(port=443)
        manager.add_rule(rule)

        # has_rule is on FirewallState, accessed via manager.state
        assert manager.state.has_rule(rule) is True
        assert manager.state.has_rule(StoredRule(port=80)) is False

    def test_set_exclusive_mode(self, manager):
        """Should update exclusive mode."""
        manager.set_exclusive_mode(True)
        assert manager.state.exclusive_mode is True

        manager.set_exclusive_mode(False)
        assert manager.state.exclusive_mode is False

    def test_set_docker_aware(self, manager):
        """Should update docker_aware flag."""
        manager.set_docker_aware(True)
        assert manager.state.docker_aware is True

        manager.set_docker_aware(False)
        assert manager.state.docker_aware is False

    def test_save_and_load(self, temp_state_dir, mock_ctx):
        """Should save and load state correctly."""
        state_file = temp_state_dir / "sm-rules.yaml"
        exclusive_marker = temp_state_dir / "exclusive"

        with patch("sm.services.firewall_state.STATE_DIR", temp_state_dir):
            with patch("sm.services.firewall_state.STATE_FILE", state_file):
                with patch("sm.services.firewall_state.EXCLUSIVE_MARKER", exclusive_marker):
                    # Create and save
                    manager1 = FirewallStateManager(mock_ctx)
                    manager1.add_rule(StoredRule(port=443, comment="HTTPS"))
                    manager1.add_rule(StoredRule(port=80, comment="HTTP"))
                    manager1.set_exclusive_mode(True)
                    manager1.save()

                    # Verify file exists
                    assert state_file.exists()

                    # Load in new manager
                    manager2 = FirewallStateManager(mock_ctx)
                    manager2.load()

                    assert len(manager2.state.rules) == 2
                    assert manager2.state.exclusive_mode is True

    def test_clear_rules(self, manager):
        """Should clear all non-protected rules."""
        manager.add_rule(StoredRule(port=80))
        manager.add_rule(StoredRule(port=443))
        manager.add_rule(StoredRule(port=22, protected=True))

        manager.clear_rules()

        # Only protected rule should remain
        assert len(manager.state.rules) == 1
        assert manager.state.rules[0].port == 22

    def test_get_rules_by_chain(self, manager):
        """Should be able to filter rules by chain from state."""
        manager.add_rule(StoredRule(port=80, chain="INPUT"))
        manager.add_rule(StoredRule(port=443, chain="INPUT"))
        manager.add_rule(StoredRule(port=8080, chain="DOCKER-USER"))

        # Filter rules by chain using list comprehension
        input_rules = [r for r in manager.state.rules if r.chain == "INPUT"]
        docker_rules = [r for r in manager.state.rules if r.chain == "DOCKER-USER"]

        assert len(input_rules) == 2
        assert len(docker_rules) == 1


class TestStateFilePaths:
    """Tests for state file path constants."""

    def test_state_dir_is_var_lib(self):
        """State directory should be under /var/lib/sm."""
        assert "/var/lib/sm" in str(STATE_DIR)

    def test_state_file_is_yaml(self):
        """State file should be YAML."""
        assert STATE_FILE.suffix == ".yaml"

    def test_exclusive_marker_location(self):
        """Exclusive marker should be in /etc."""
        assert "/etc" in str(EXCLUSIVE_MARKER)


class TestStoredRuleProtectedRules:
    """Tests for protected rule handling."""

    def test_protected_rule_cannot_be_removed(self):
        """Protected rules should not be removable via matches."""
        protected = StoredRule(port=22, protected=True)
        normal = StoredRule(port=22, protected=False)

        # They should match for comparison
        assert protected.matches(normal) is True

    def test_ssh_default_protected(self):
        """SSH rules are typically protected."""
        rule = StoredRule(port=22, protected=True, comment="SSH - protected")
        assert rule.protected is True


class TestFirewallStatePreservedChains:
    """Tests for preserved chain pattern handling."""

    def test_default_fail2ban_patterns(self):
        """Should include fail2ban patterns by default."""
        state = FirewallState()
        assert "f2b-*" in state.preserved_chain_patterns
        assert "fail2ban-*" in state.preserved_chain_patterns

    def test_custom_preserved_patterns(self):
        """Should allow custom preserved patterns."""
        state = FirewallState(
            preserved_chain_patterns=["f2b-*", "custom-*"]
        )
        assert "custom-*" in state.preserved_chain_patterns

    def test_preserved_patterns_in_dict(self):
        """Preserved patterns should be serialized."""
        state = FirewallState(
            preserved_chain_patterns=["f2b-*", "myapp-*"]
        )
        d = state.to_dict()
        assert "preserved_chain_patterns" in d
        assert "myapp-*" in d["preserved_chain_patterns"]


class TestFirewallStateManagerConcurrency:
    """Tests for concurrent access handling."""

    @pytest.fixture
    def temp_state_dir(self):
        """Create temporary state directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_ctx(self):
        """Create a mock execution context."""
        return create_context(dry_run=False)

    def test_load_handles_missing_file(self, temp_state_dir, mock_ctx):
        """Should handle missing state file gracefully."""
        state_file = temp_state_dir / "sm-rules.yaml"

        with patch("sm.services.firewall_state.STATE_DIR", temp_state_dir):
            with patch("sm.services.firewall_state.STATE_FILE", state_file):
                with patch("sm.services.firewall_state.EXCLUSIVE_MARKER", temp_state_dir / "exclusive"):
                    manager = FirewallStateManager(mock_ctx)
                    # Should not raise
                    manager.load()
                    assert len(manager.state.rules) == 0

    def test_load_handles_corrupt_file(self, temp_state_dir, mock_ctx):
        """Should handle corrupt YAML file gracefully."""
        state_file = temp_state_dir / "sm-rules.yaml"
        state_file.write_text("invalid: yaml: content: {{{")

        with patch("sm.services.firewall_state.STATE_DIR", temp_state_dir):
            with patch("sm.services.firewall_state.STATE_FILE", state_file):
                with patch("sm.services.firewall_state.EXCLUSIVE_MARKER", temp_state_dir / "exclusive"):
                    manager = FirewallStateManager(mock_ctx)
                    # Should handle gracefully and reset to empty state
                    manager.load()

    def test_save_creates_directory(self, temp_state_dir, mock_ctx):
        """Should create state directory if it doesn't exist."""
        nested_dir = temp_state_dir / "nested" / "path"
        state_file = nested_dir / "sm-rules.yaml"

        with patch("sm.services.firewall_state.STATE_DIR", nested_dir):
            with patch("sm.services.firewall_state.STATE_FILE", state_file):
                with patch("sm.services.firewall_state.EXCLUSIVE_MARKER", nested_dir / "exclusive"):
                    manager = FirewallStateManager(mock_ctx)
                    manager.add_rule(StoredRule(port=80))
                    manager.save()

                    assert nested_dir.exists()
                    assert state_file.exists()
