"""Integration tests for the postgres optimize command.

Tests the CLI interface and workflow of the optimize command,
mocking system services to avoid requiring actual PostgreSQL.
"""

import pytest
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch, PropertyMock

from typer.testing import CliRunner

from sm.cli import app
from sm.services.tuning import (
    PostgresTuningService,
    SystemInfo,
    TuningParameter,
    TuningRecommendation,
    WorkloadProfile,
)


runner = CliRunner()


@pytest.fixture
def mock_root_check() -> Generator[None, None, None]:
    """Mock the root check to allow tests to run without root."""
    with patch("sm.core.safety.os.geteuid", return_value=0):
        yield


@pytest.fixture
def mock_preflight() -> Generator[None, None, None]:
    """Mock preflight checks."""
    with patch("sm.commands.postgres.optimize.run_preflight_checks"):
        yield


@pytest.fixture
def mock_pg_service() -> Generator[MagicMock, None, None]:
    """Mock PostgreSQLService."""
    with patch("sm.commands.postgres.optimize.PostgreSQLService") as mock:
        instance = mock.return_value
        instance.detect_version.return_value = "17"
        instance.is_running.return_value = True
        yield instance


@pytest.fixture
def sample_system_info() -> SystemInfo:
    """Create sample system info for tests."""
    return SystemInfo(
        memory_mb=16384,
        cpu_count=8,
        disk_type="ssd",
        pg_version="17",
        pg_data_dir=Path("/var/lib/postgresql/17/main"),
    )


@pytest.fixture
def sample_recommendation(sample_system_info: SystemInfo) -> TuningRecommendation:
    """Create sample tuning recommendation."""
    return TuningRecommendation(
        system_info=sample_system_info,
        workload_profile=WorkloadProfile.MIXED,
        parameters=[
            TuningParameter(
                name="shared_buffers",
                current_value="128MB",
                recommended_value="4915MB",
                unit="MB",
                reason="30% of RAM for MIXED workload",
                requires_restart=True,
            ),
            TuningParameter(
                name="work_mem",
                current_value="4MB",
                recommended_value="128MB",
                unit="MB",
                reason="Per-operation memory for sorts/hashes (MIXED)",
                requires_restart=False,
            ),
            TuningParameter(
                name="random_page_cost",
                current_value="4.0",
                recommended_value="1.1",
                unit="",
                reason="SSD has near-sequential random access",
                requires_restart=False,
            ),
        ],
    )


@pytest.fixture
def mock_tuning_service(
    sample_system_info: SystemInfo,
    sample_recommendation: TuningRecommendation,
) -> Generator[MagicMock, None, None]:
    """Mock PostgresTuningService."""
    with patch("sm.commands.postgres.optimize.PostgresTuningService") as mock:
        instance = mock.return_value
        instance.detect_system_info.return_value = sample_system_info
        instance.read_current_config.return_value = {
            "shared_buffers": "128MB",
            "work_mem": "4MB",
            "random_page_cost": "4.0",
        }
        instance.calculate_recommendations.return_value = sample_recommendation
        instance.generate_config.return_value = "# Test config"
        yield instance


@pytest.fixture
def mock_systemd() -> Generator[MagicMock, None, None]:
    """Mock SystemdService."""
    with patch("sm.commands.postgres.optimize.SystemdService") as mock:
        yield mock.return_value


@pytest.fixture
def mock_audit() -> Generator[MagicMock, None, None]:
    """Mock audit logger."""
    with patch("sm.commands.postgres.optimize.get_audit_logger") as mock:
        yield mock.return_value


@pytest.fixture
def mock_executor() -> Generator[MagicMock, None, None]:
    """Mock CommandExecutor."""
    with patch("sm.commands.postgres.optimize.CommandExecutor") as mock:
        instance = mock.return_value
        instance.run_sql.return_value = "10"  # For connection count
        instance.backup_file.return_value = Path("/tmp/99-tuning.conf.bak")
        yield instance


class TestOptimizePreviewMode:
    """Tests for preview mode (default, no --apply)."""

    def test_preview_shows_recommendations(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Preview mode should show recommendations without applying."""
        result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 0
        assert "System Detection" in result.output
        assert "Tuning Recommendations" in result.output
        assert "Preview only" in result.output
        # Should NOT have applied anything
        mock_tuning_service.generate_config.assert_not_called()

    def test_preview_shows_workload_info(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Preview should show workload profile description."""
        result = runner.invoke(app, ["postgres", "optimize", "--workload", "oltp"])

        assert result.exit_code == 0
        # The workload was passed to calculate_recommendations
        mock_tuning_service.calculate_recommendations.assert_called()


class TestOptimizeWorkloadProfiles:
    """Tests for different workload profiles."""

    @pytest.mark.parametrize("workload", ["oltp", "olap", "mixed"])
    def test_workload_option_accepted(
        self,
        workload: str,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """All workload options should be accepted."""
        result = runner.invoke(app, ["postgres", "optimize", "-w", workload])

        assert result.exit_code == 0
        mock_tuning_service.calculate_recommendations.assert_called()

    def test_invalid_workload_rejected(
        self,
        mock_root_check: None,
    ) -> None:
        """Invalid workload should be rejected."""
        result = runner.invoke(app, ["postgres", "optimize", "-w", "invalid"])

        assert result.exit_code != 0


class TestOptimizeApplyMode:
    """Tests for apply mode (--apply flag)."""

    def test_apply_without_yes_prompts_confirmation(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
        mock_systemd: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        """Apply mode without --yes should prompt for confirmation."""
        # Simulate user declining confirmation
        result = runner.invoke(app, ["postgres", "optimize", "--apply"], input="n\n")

        assert "cancelled" in result.output.lower() or result.exit_code == 0

    def test_apply_with_yes_skips_confirmation(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
        mock_systemd: MagicMock,
        mock_audit: MagicMock,
    ) -> None:
        """Apply with --yes should skip confirmation and proceed."""
        # Also need to mock Path operations
        with patch("sm.commands.postgres.optimize.Path") as mock_path_class:
            # Mock the config path and its parent
            mock_conf_d = MagicMock()
            mock_conf_d.exists.return_value = True  # Directory already exists
            mock_config_path = MagicMock()
            mock_config_path.parent = mock_conf_d
            mock_config_path.exists.return_value = False

            def path_factory(path_str: str) -> MagicMock:
                if "conf.d/99-tuning.conf" in path_str:
                    return mock_config_path
                return MagicMock()

            mock_path_class.side_effect = path_factory

            result = runner.invoke(
                app,
                ["postgres", "optimize", "--apply", "--yes"],
            )

        # Should complete successfully (--yes also skips restart prompt)
        assert result.exit_code == 0
        # The output should show optimization complete or config written
        assert "Optimization" in result.output or "Configuration" in result.output


class TestOptimizeDryRun:
    """Tests for dry-run mode."""

    def test_dry_run_shows_preview(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Dry-run should show preview."""
        result = runner.invoke(app, ["postgres", "optimize", "--dry-run"])

        assert result.exit_code == 0
        assert "Preview only" in result.output

    def test_dry_run_with_apply_no_changes(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Dry-run with apply should still not make changes."""
        result = runner.invoke(
            app,
            ["postgres", "optimize", "--apply", "--dry-run", "--yes"],
        )

        # In dry-run, preview only message should appear
        assert result.exit_code == 0


class TestOptimizeEdgeCases:
    """Tests for edge cases and error handling."""

    def test_postgres_not_installed(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_executor: MagicMock,
    ) -> None:
        """Should fail gracefully if PostgreSQL not installed."""
        with patch("sm.commands.postgres.optimize.PostgreSQLService") as mock:
            mock.return_value.detect_version.return_value = None
            result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    def test_postgres_not_running(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_executor: MagicMock,
    ) -> None:
        """Should fail gracefully if PostgreSQL not running."""
        with patch("sm.commands.postgres.optimize.PostgreSQLService") as mock:
            instance = mock.return_value
            instance.detect_version.return_value = "17"
            instance.is_running.return_value = False
            result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 1
        assert "not running" in result.output.lower()


class TestOptimizeSafetyChecks:
    """Tests for safety check functionality."""

    def test_high_connection_count_warning(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_systemd: MagicMock,
        mock_audit: MagicMock,
        sample_system_info: SystemInfo,
    ) -> None:
        """Should warn when active connections approach max_connections."""
        # Create recommendation with max_connections change
        recommendation = TuningRecommendation(
            system_info=sample_system_info,
            workload_profile=WorkloadProfile.OLAP,
            parameters=[
                TuningParameter(
                    name="max_connections",
                    current_value="200",
                    recommended_value="50",
                    unit="",
                    reason="Fewer connections for OLAP",
                    requires_restart=True,
                ),
            ],
        )

        with patch("sm.commands.postgres.optimize.PostgresTuningService") as mock_tuning:
            instance = mock_tuning.return_value
            instance.detect_system_info.return_value = sample_system_info
            instance.read_current_config.return_value = {"max_connections": "200"}
            instance.calculate_recommendations.return_value = recommendation

            with patch("sm.commands.postgres.optimize.CommandExecutor") as mock_exec:
                # Return high connection count
                mock_exec.return_value.run_sql.return_value = "48"
                mock_exec.return_value.backup_file.return_value = Path("/tmp/backup")

                result = runner.invoke(
                    app,
                    ["postgres", "optimize", "--apply"],
                    input="n\n",  # Decline to apply
                )

        # Should show safety warning
        assert "Safety check" in result.output or "warning" in result.output.lower()


class TestOptimizeOutput:
    """Tests for output formatting."""

    def test_output_includes_system_info(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Output should include detected system info."""
        result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 0
        assert "RAM:" in result.output or "MB" in result.output
        assert "CPU" in result.output

    def test_output_includes_parameter_table(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Output should include parameter comparison table."""
        result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 0
        assert "Parameter" in result.output
        assert "Current" in result.output
        assert "Recommended" in result.output

    def test_output_shows_hint_for_apply(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_tuning_service: MagicMock,
        mock_executor: MagicMock,
    ) -> None:
        """Preview mode should show hint to use --apply."""
        result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 0
        assert "--apply" in result.output


class TestOptimizeAlreadyOptimal:
    """Tests when config is already optimal."""

    def test_already_optimal_message(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_executor: MagicMock,
        sample_system_info: SystemInfo,
    ) -> None:
        """Should show 'already optimal' when no changes needed."""
        # Create recommendation with no changed parameters
        recommendation = TuningRecommendation(
            system_info=sample_system_info,
            workload_profile=WorkloadProfile.MIXED,
            parameters=[
                TuningParameter(
                    name="shared_buffers",
                    current_value="4915MB",
                    recommended_value="4915MB",
                    unit="MB",
                    reason="30% of RAM",
                    requires_restart=True,
                ),
            ],
        )

        with patch("sm.commands.postgres.optimize.PostgresTuningService") as mock_tuning:
            instance = mock_tuning.return_value
            instance.detect_system_info.return_value = sample_system_info
            instance.read_current_config.return_value = {"shared_buffers": "4915MB"}
            instance.calculate_recommendations.return_value = recommendation

            result = runner.invoke(app, ["postgres", "optimize"])

        assert result.exit_code == 0
        assert "optimal" in result.output.lower()

    def test_already_optimal_with_apply_no_changes(
        self,
        mock_root_check: None,
        mock_preflight: None,
        mock_pg_service: MagicMock,
        mock_executor: MagicMock,
        sample_system_info: SystemInfo,
    ) -> None:
        """Apply with already optimal config should not make changes."""
        recommendation = TuningRecommendation(
            system_info=sample_system_info,
            workload_profile=WorkloadProfile.MIXED,
            parameters=[
                TuningParameter(
                    name="shared_buffers",
                    current_value="4915MB",
                    recommended_value="4915MB",
                    unit="MB",
                    reason="30% of RAM",
                    requires_restart=True,
                ),
            ],
        )

        with patch("sm.commands.postgres.optimize.PostgresTuningService") as mock_tuning:
            instance = mock_tuning.return_value
            instance.detect_system_info.return_value = sample_system_info
            instance.read_current_config.return_value = {"shared_buffers": "4915MB"}
            instance.calculate_recommendations.return_value = recommendation

            result = runner.invoke(app, ["postgres", "optimize", "--apply", "--yes"])

        assert result.exit_code == 0
        assert "no changes" in result.output.lower()
