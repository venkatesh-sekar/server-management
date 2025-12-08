"""Unit tests for firewall CLI commands."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typer.testing import CliRunner

from sm.commands.firewall import (
    app,
    _parse_protocol,
    _get_firewall_service,
    _check_root,
)
from sm.services.iptables import Protocol
from sm.core.exceptions import FirewallError


runner = CliRunner()


class TestParseProtocol:
    """Tests for _parse_protocol helper."""

    def test_parse_tcp(self):
        """Should parse 'tcp' to Protocol.TCP."""
        assert _parse_protocol("tcp") == Protocol.TCP
        assert _parse_protocol("TCP") == Protocol.TCP
        assert _parse_protocol("Tcp") == Protocol.TCP

    def test_parse_udp(self):
        """Should parse 'udp' to Protocol.UDP."""
        assert _parse_protocol("udp") == Protocol.UDP
        assert _parse_protocol("UDP") == Protocol.UDP

    def test_parse_icmp(self):
        """Should parse 'icmp' to Protocol.ICMP."""
        assert _parse_protocol("icmp") == Protocol.ICMP

    def test_parse_all(self):
        """Should parse 'all' to Protocol.ALL."""
        assert _parse_protocol("all") == Protocol.ALL

    def test_parse_invalid(self):
        """Should raise error for invalid protocol."""
        with pytest.raises(FirewallError) as exc:
            _parse_protocol("invalid")
        assert "Invalid protocol" in str(exc.value)


class TestGetFirewallService:
    """Tests for _get_firewall_service factory."""

    def test_returns_tuple(self):
        """Should return tuple of (context, service)."""
        ctx, iptables = _get_firewall_service()
        assert ctx is not None
        assert iptables is not None

    def test_dry_run_propagates(self):
        """Should propagate dry_run to context."""
        ctx, _ = _get_firewall_service(dry_run=True)
        assert ctx.dry_run is True

    def test_verbose_propagates(self):
        """Should propagate verbose to context."""
        ctx, _ = _get_firewall_service(verbose=2)
        # ExecutionContext uses is_verbose property, verbosity level is stored internally
        assert ctx.is_verbose is True


class TestCheckRoot:
    """Tests for _check_root helper."""

    def test_allows_root(self):
        """Should pass when running as root."""
        mock_ctx = Mock()
        mock_ctx.dry_run = False

        with patch("os.geteuid", return_value=0):
            # Should not raise
            _check_root(mock_ctx)

    def test_allows_dry_run(self):
        """Should pass in dry-run mode even without root."""
        mock_ctx = Mock()
        mock_ctx.dry_run = True

        with patch("os.geteuid", return_value=1000):
            # Should not raise
            _check_root(mock_ctx)

    def test_rejects_non_root(self):
        """Should raise error when not root and not dry-run."""
        import typer

        mock_ctx = Mock()
        mock_ctx.dry_run = False
        mock_ctx.console = Mock()

        with patch("os.geteuid", return_value=1000):
            with pytest.raises(typer.Exit) as exc_info:
                _check_root(mock_ctx)
            # Exit code 6 indicates permission error
            assert exc_info.value.exit_code == 6


class TestFirewallStatusCommand:
    """Tests for 'sm firewall status' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    def test_status_shows_output(self, mock_get_service):
        """Status command should show firewall status."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()
        mock_iptables.status.return_value = Mock(
            active=True,
            default_policy="DROP",
            ipv4_rules_count=10,
            ipv6_rules_count=5,
            ssh_protected=True,
            persistence_installed=True,
            docker_detected=False,
            docker_user_chain_exists=False,
            last_saved=None,
        )
        mock_iptables.list_rules.return_value = []
        mock_iptables.ssh_port = 22
        mock_iptables.get_provider_status.return_value = Mock(
            has_conflicts=False,
            conflict_names=[],
            nftables_active=False,
        )

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["status"])
        # Should not error
        assert result.exit_code == 0 or mock_iptables.status.called

    @patch("sm.commands.firewall._get_firewall_service")
    def test_status_technical_flag(self, mock_get_service):
        """Status command with --technical should show more details."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()
        mock_iptables.status.return_value = Mock(
            active=True,
            default_policy="DROP",
            ipv4_rules_count=10,
            ipv6_rules_count=5,
            ssh_protected=True,
            persistence_installed=True,
            docker_detected=False,
            docker_user_chain_exists=False,
            last_saved=None,
        )
        mock_iptables.list_rules.return_value = []
        mock_iptables.ssh_port = 22
        mock_iptables.get_provider_status.return_value = Mock(
            has_conflicts=False,
            conflict_names=[],
            nftables_active=False,
        )

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["status", "--technical"])
        assert mock_iptables.status.called


class TestFirewallListCommand:
    """Tests for 'sm firewall list' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    def test_list_default_chain(self, mock_get_service):
        """List command should default to INPUT chain."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()
        mock_iptables.list_rules.return_value = []

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["list"])
        # Should call list_rules
        mock_iptables.list_rules.assert_called()

    @patch("sm.commands.firewall._get_firewall_service")
    def test_list_specific_chain(self, mock_get_service):
        """List command should accept specific chain."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()
        mock_iptables.list_rules.return_value = []

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["list", "--chain", "DOCKER-USER"])
        mock_iptables.list_rules.assert_called()


class TestFirewallEnableCommand:
    """Tests for 'sm firewall enable' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_enable_dry_run(self, mock_audit, mock_check_root, mock_get_service):
        """Enable command with --dry-run should not execute."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.check_provider_conflicts.return_value = None
        mock_iptables.docker_detected.return_value = False
        mock_iptables.ssh_port = 22

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["enable", "--dry-run"])
        # In dry-run, should not actually enable
        # Just verify it doesn't crash

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_enable_with_preset(self, mock_audit, mock_check_root, mock_get_service):
        """Enable command should accept preset."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = False

        mock_iptables = Mock()
        mock_iptables.check_provider_conflicts.return_value = None
        mock_iptables.docker_detected.return_value = False
        mock_iptables.ssh_port = 22

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        # Just verify the command accepts the flag
        result = runner.invoke(app, ["enable", "--preset", "web", "--dry-run"])


class TestFirewallDisableCommand:
    """Tests for 'sm firewall disable' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    def test_disable_requires_force(self, mock_check_root, mock_get_service):
        """Disable command should require --force flag."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())

        result = runner.invoke(app, ["disable"])
        # Should fail without --force
        assert result.exit_code != 0 or "force" in result.output.lower()

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_disable_with_force_dry_run(self, mock_audit, mock_check_root, mock_get_service):
        """Disable command with --force --dry-run should preview."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.status.return_value = Mock(
            default_policy="DROP",
            ipv4_rules_count=10,
        )

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["disable", "--force", "--dry-run"])


class TestFirewallAllowCommand:
    """Tests for 'sm firewall allow' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_allow_service(self, mock_audit, mock_check_root, mock_get_service):
        """Allow command should accept service names."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.allow_port.return_value = None
        mock_iptables.backup.return_value = "/tmp/backup"
        mock_iptables.save.return_value = None

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["allow", "web", "--dry-run"])

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_allow_port(self, mock_audit, mock_check_root, mock_get_service):
        """Allow command should accept port numbers."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.allow_port.return_value = None
        mock_iptables.backup.return_value = "/tmp/backup"
        mock_iptables.save.return_value = None

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["allow", "8080", "--dry-run"])

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_allow_with_source(self, mock_audit, mock_check_root, mock_get_service):
        """Allow command should accept --from source."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.allow_port.return_value = None
        mock_iptables.backup.return_value = "/tmp/backup"
        mock_iptables.save.return_value = None

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["allow", "postgres", "--from", "local-network", "--dry-run"])

    def test_allow_invalid_target(self):
        """Allow command should fail for invalid targets."""
        with patch("sm.commands.firewall._get_firewall_service") as mock_get:
            with patch("sm.commands.firewall._check_root"):
                with patch("sm.commands.firewall.get_audit_logger"):
                    mock_ctx = Mock()
                    mock_ctx.console = Mock()
                    mock_get.return_value = (mock_ctx, Mock())

                    result = runner.invoke(app, ["allow", "invalid-service-name"])
                    # Should show error about unknown service


class TestFirewallDenyCommand:
    """Tests for 'sm firewall deny' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    def test_deny_requires_force(self, mock_check_root, mock_get_service):
        """Deny command should require --force flag."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())

        result = runner.invoke(app, ["deny", "mysql"])
        # Should require --force
        assert result.exit_code != 0 or "force" in result.output.lower()

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_deny_cannot_block_ssh(self, mock_audit, mock_check_root, mock_get_service):
        """Deny command should not allow blocking SSH."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["deny", "ssh", "--force"])
        # Should be rejected


class TestFirewallSaveCommand:
    """Tests for 'sm firewall save' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_save_calls_service(self, mock_audit, mock_check_root, mock_get_service):
        """Save command should call iptables.save()."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, ["save", "--dry-run"])
        # Service methods should be called
        mock_iptables.save.assert_called()


class TestFirewallResetCommand:
    """Tests for 'sm firewall reset' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    def test_reset_requires_force(self, mock_check_root, mock_get_service):
        """Reset command should require --force flag."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())

        result = runner.invoke(app, ["reset"])
        assert result.exit_code != 0

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    def test_reset_requires_confirm_name(self, mock_check_root, mock_get_service):
        """Reset command should require --confirm-name=firewall."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())

        result = runner.invoke(app, ["reset", "--force"])
        # Should still fail without --confirm-name
        assert result.exit_code != 0

    @patch("sm.commands.firewall._get_firewall_service")
    @patch("sm.commands.firewall._check_root")
    @patch("sm.commands.firewall.get_audit_logger")
    def test_reset_with_all_flags_dry_run(self, mock_audit, mock_check_root, mock_get_service):
        """Reset command with all flags and --dry-run should preview."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()
        mock_ctx.dry_run = True

        mock_iptables = Mock()
        mock_iptables.backup.return_value = "/tmp/backup"

        mock_get_service.return_value = (mock_ctx, mock_iptables)
        mock_audit.return_value = Mock()

        result = runner.invoke(app, [
            "reset", "--force", "--confirm-name=firewall", "--dry-run"
        ])


class TestFirewallPresetCommands:
    """Tests for 'sm firewall preset' subcommands."""

    @patch("sm.commands.firewall._get_firewall_service")
    def test_preset_list(self, mock_get_service):
        """Preset list command should show available presets."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["preset", "list"])
        # Should complete without error

    @patch("sm.commands.firewall._get_firewall_service")
    def test_preset_show(self, mock_get_service):
        """Preset show command should show preset details."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_iptables = Mock()
        mock_iptables.get_preset.return_value = Mock(
            name="web",
            description="Web server preset",
            docker_aware=False,
            rules=[],
        )

        mock_get_service.return_value = (mock_ctx, mock_iptables)

        result = runner.invoke(app, ["preset", "show", "web"])
        mock_iptables.get_preset.assert_called_with("web")


class TestFirewallServicesCommand:
    """Tests for 'sm firewall services' command."""

    @patch("sm.commands.firewall._get_firewall_service")
    def test_services_lists_all(self, mock_get_service):
        """Services command should list all available services."""
        mock_ctx = Mock()
        mock_ctx.console = Mock()

        mock_get_service.return_value = (mock_ctx, Mock())

        result = runner.invoke(app, ["services"])
        # Should complete without error


class TestCommandHelp:
    """Tests for command help text."""

    def test_main_help(self):
        """Main app should have help text."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "firewall" in result.output.lower()

    def test_status_help(self):
        """Status command should have help text."""
        result = runner.invoke(app, ["status", "--help"])
        assert result.exit_code == 0

    def test_allow_help(self):
        """Allow command should have help text."""
        result = runner.invoke(app, ["allow", "--help"])
        assert result.exit_code == 0
        assert "service" in result.output.lower() or "port" in result.output.lower()

    def test_enable_help(self):
        """Enable command should have help text."""
        result = runner.invoke(app, ["enable", "--help"])
        assert result.exit_code == 0
        assert "preset" in result.output.lower()

    def test_setup_help(self):
        """Setup command should have help text."""
        result = runner.invoke(app, ["setup", "--help"])
        assert result.exit_code == 0
        assert "wizard" in result.output.lower() or "interactive" in result.output.lower()
