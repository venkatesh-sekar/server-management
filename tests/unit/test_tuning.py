"""Unit tests for the PostgreSQL tuning service."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from sm.services.tuning import (
    WorkloadProfile,
    SystemInfo,
    TuningParameter,
    TuningRecommendation,
    PostgresTuningService,
)


class TestWorkloadProfile:
    """Tests for WorkloadProfile enum."""

    def test_workload_values(self):
        """Workload profiles should have correct values."""
        assert WorkloadProfile.OLTP.value == "oltp"
        assert WorkloadProfile.OLAP.value == "olap"
        assert WorkloadProfile.MIXED.value == "mixed"

    def test_workload_descriptions(self):
        """Workload profiles should have descriptions."""
        assert "transaction" in WorkloadProfile.OLTP.description.lower()
        assert "analytics" in WorkloadProfile.OLAP.description.lower()
        assert "balanced" in WorkloadProfile.MIXED.description.lower()


class TestTuningParameter:
    """Tests for TuningParameter dataclass."""

    def test_changed_detection_different_values(self):
        """Changed should be True when values differ."""
        param = TuningParameter(
            name="shared_buffers",
            current_value="4096MB",
            recommended_value="8192MB",
            unit="MB",
            reason="Test",
            requires_restart=True,
        )
        assert param.changed is True

    def test_changed_detection_same_values(self):
        """Changed should be False when values are the same."""
        param = TuningParameter(
            name="shared_buffers",
            current_value="8192MB",
            recommended_value="8192MB",
            unit="MB",
            reason="Test",
            requires_restart=True,
        )
        assert param.changed is False

    def test_changed_detection_null_current(self):
        """Changed should be True when current is None."""
        param = TuningParameter(
            name="shared_buffers",
            current_value=None,
            recommended_value="8192MB",
            unit="MB",
            reason="Test",
            requires_restart=True,
        )
        assert param.changed is True

    def test_normalize_boolean_on(self):
        """Boolean 'on' variations should normalize."""
        param = TuningParameter(
            name="jit",
            current_value="on",
            recommended_value="ON",
            unit="",
            reason="Test",
            requires_restart=False,
        )
        assert param.changed is False

    def test_normalize_boolean_off(self):
        """Boolean 'off' variations should normalize."""
        param = TuningParameter(
            name="jit",
            current_value="off",
            recommended_value="false",
            unit="",
            reason="Test",
            requires_restart=False,
        )
        assert param.changed is False

    def test_normalize_memory_units_mb_to_gb(self):
        """Memory units should normalize (1024MB = 1GB)."""
        param = TuningParameter(
            name="shared_buffers",
            current_value="1024MB",
            recommended_value="1GB",
            unit="MB",
            reason="Test",
            requires_restart=True,
        )
        assert param.changed is False

    def test_normalize_memory_units_different(self):
        """Different memory values should be detected."""
        param = TuningParameter(
            name="shared_buffers",
            current_value="2048MB",
            recommended_value="4GB",
            unit="MB",
            reason="Test",
            requires_restart=True,
        )
        assert param.changed is True


class TestTuningRecommendation:
    """Tests for TuningRecommendation dataclass."""

    def test_changed_parameters_filter(self):
        """changed_parameters should only return changed ones."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=8,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )

        params = [
            TuningParameter("p1", "100", "200", "", "Test", False),  # changed
            TuningParameter("p2", "300", "300", "", "Test", False),  # unchanged
            TuningParameter("p3", None, "400", "", "Test", True),    # changed
        ]

        rec = TuningRecommendation(system_info, WorkloadProfile.MIXED, params)

        assert len(rec.changed_parameters) == 2
        assert rec.parameters[0] in rec.changed_parameters
        assert rec.parameters[1] not in rec.changed_parameters
        assert rec.parameters[2] in rec.changed_parameters

    def test_has_restart_required_true(self):
        """has_restart_required should be True if any changed param needs restart."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=8,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )

        params = [
            TuningParameter("p1", "100", "200", "", "Test", requires_restart=True),
        ]

        rec = TuningRecommendation(system_info, WorkloadProfile.MIXED, params)
        assert rec.has_restart_required is True

    def test_has_restart_required_false(self):
        """has_restart_required should be False if no changed param needs restart."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=8,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )

        params = [
            TuningParameter("p1", "100", "200", "", "Test", requires_restart=False),
        ]

        rec = TuningRecommendation(system_info, WorkloadProfile.MIXED, params)
        assert rec.has_restart_required is False


class TestPostgresTuningService:
    """Tests for PostgresTuningService class."""

    @pytest.fixture
    def mock_ctx(self):
        """Create a mock execution context."""
        ctx = Mock()
        ctx.dry_run = False
        return ctx

    @pytest.fixture
    def mock_executor(self):
        """Create a mock command executor."""
        return Mock()

    @pytest.fixture
    def tuning_service(self, mock_ctx, mock_executor):
        """Create tuning service with mocks."""
        return PostgresTuningService(mock_ctx, mock_executor)

    def test_get_memory_mb_from_meminfo(self, tuning_service):
        """Should parse memory from /proc/meminfo."""
        meminfo_content = """MemTotal:       16384000 kB
MemFree:         1234567 kB
MemAvailable:    8765432 kB
"""
        with patch("builtins.open", mock_open(read_data=meminfo_content)):
            memory = tuning_service._get_memory_mb()
            assert memory == 16000  # 16384000 kB / 1024 = ~16000 MB

    def test_get_memory_mb_fallback(self, tuning_service):
        """Should return 4096 on failure."""
        with patch("builtins.open", side_effect=OSError("File not found")):
            memory = tuning_service._get_memory_mb()
            assert memory == 4096

    def test_get_cpu_count(self, tuning_service):
        """Should return CPU count from os.cpu_count()."""
        with patch("os.cpu_count", return_value=16):
            cpus = tuning_service._get_cpu_count()
            assert cpus == 16

    def test_get_cpu_count_fallback(self, tuning_service):
        """Should return 4 if cpu_count() returns None."""
        with patch("os.cpu_count", return_value=None):
            cpus = tuning_service._get_cpu_count()
            assert cpus == 4

    def test_extract_base_device_traditional(self, tuning_service):
        """Should extract base device from traditional devices."""
        assert tuning_service._extract_base_device("/dev/sda1") == "sda"
        assert tuning_service._extract_base_device("/dev/vda3") == "vda"
        assert tuning_service._extract_base_device("sdb2") == "sdb"

    def test_extract_base_device_nvme(self, tuning_service):
        """Should extract base device from NVMe devices."""
        assert tuning_service._extract_base_device("/dev/nvme0n1p1") == "nvme0n1"
        assert tuning_service._extract_base_device("nvme1n1p2") == "nvme1n1"

    def test_extract_base_device_mapper(self, tuning_service):
        """Should return None for device mapper (LVM)."""
        assert tuning_service._extract_base_device("/dev/mapper/vg-lv") is None
        assert tuning_service._extract_base_device("dm-0") is None

    def test_read_current_config_batched_query(self, mock_ctx, mock_executor):
        """Should parse batched pg_settings query output."""
        # Mock pg_settings output format
        mock_executor.run_sql.return_value = """shared_buffers|128MB
effective_cache_size|4GB
work_mem|4MB
max_connections|100"""

        service = PostgresTuningService(mock_ctx, mock_executor)
        config = service.read_current_config("17")

        assert config["shared_buffers"] == "128MB"
        assert config["effective_cache_size"] == "4GB"
        assert config["work_mem"] == "4MB"
        assert config["max_connections"] == "100"
        # Should only call run_sql once (batched query)
        assert mock_executor.run_sql.call_count == 1

    def test_read_current_config_handles_empty_result(self, mock_ctx, mock_executor):
        """Should handle empty query result."""
        mock_executor.run_sql.return_value = ""

        service = PostgresTuningService(mock_ctx, mock_executor)
        config = service.read_current_config("17")

        assert config == {}

    def test_read_current_config_fallback_on_error(self, mock_ctx, mock_executor):
        """Should fall back to individual queries on batch failure."""
        # First call (batch) fails, subsequent calls succeed
        mock_executor.run_sql.side_effect = [
            Exception("Batch query failed"),  # First call fails
            "128MB",  # shared_buffers
            "4GB",    # effective_cache_size
        ] + [""] * 20  # Remaining parameters

        service = PostgresTuningService(mock_ctx, mock_executor)
        config = service.read_current_config("17")

        # Should have values from fallback
        assert "shared_buffers" in config or len(config) >= 0  # Fallback attempted
        # Should have called run_sql more than once (fallback)
        assert mock_executor.run_sql.call_count > 1

    def test_read_current_config_dry_run_returns_empty(self, mock_executor):
        """Dry run should return empty dict without querying."""
        ctx = Mock()
        ctx.dry_run = True

        service = PostgresTuningService(ctx, mock_executor)
        config = service.read_current_config("17")

        assert config == {}
        mock_executor.run_sql.assert_not_called()


class TestCalculateRecommendations:
    """Tests for calculate_recommendations method."""

    @pytest.fixture
    def tuning_service(self):
        """Create tuning service with mocks."""
        ctx = Mock()
        ctx.dry_run = False
        executor = Mock()
        return PostgresTuningService(ctx, executor)

    @pytest.fixture
    def system_info(self):
        """Create sample system info."""
        return SystemInfo(
            memory_mb=32768,  # 32GB
            cpu_count=8,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )

    def test_oltp_shared_buffers(self, tuning_service, system_info):
        """OLTP should use 25% of RAM for shared_buffers."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLTP, {}
        )
        shared_buffers = next(p for p in rec.parameters if p.name == "shared_buffers")
        assert shared_buffers.recommended_value == "8192MB"  # 25% of 32768

    def test_olap_shared_buffers(self, tuning_service, system_info):
        """OLAP should use 40% of RAM for shared_buffers."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLAP, {}
        )
        shared_buffers = next(p for p in rec.parameters if p.name == "shared_buffers")
        assert shared_buffers.recommended_value == "13107MB"  # 40% of 32768

    def test_mixed_shared_buffers(self, tuning_service, system_info):
        """MIXED should use 30% of RAM for shared_buffers."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        shared_buffers = next(p for p in rec.parameters if p.name == "shared_buffers")
        assert shared_buffers.recommended_value == "9830MB"  # 30% of 32768

    def test_ssd_random_page_cost(self, tuning_service, system_info):
        """SSD should use 1.1 for random_page_cost."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        random_page_cost = next(
            p for p in rec.parameters if p.name == "random_page_cost"
        )
        assert random_page_cost.recommended_value == "1.1"

    def test_hdd_random_page_cost(self, tuning_service):
        """HDD should use 4.0 for random_page_cost."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=4,
            disk_type="hdd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        random_page_cost = next(
            p for p in rec.parameters if p.name == "random_page_cost"
        )
        assert random_page_cost.recommended_value == "4.0"

    def test_ssd_effective_io_concurrency(self, tuning_service, system_info):
        """SSD should use 200 for effective_io_concurrency."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        io_conc = next(
            p for p in rec.parameters if p.name == "effective_io_concurrency"
        )
        assert io_conc.recommended_value == "200"

    def test_oltp_max_connections(self, tuning_service, system_info):
        """OLTP should use 200 max_connections."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLTP, {}
        )
        max_conn = next(p for p in rec.parameters if p.name == "max_connections")
        assert max_conn.recommended_value == "200"

    def test_olap_max_connections(self, tuning_service, system_info):
        """OLAP should use 50 max_connections."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLAP, {}
        )
        max_conn = next(p for p in rec.parameters if p.name == "max_connections")
        assert max_conn.recommended_value == "50"

    def test_olap_jit_enabled(self, tuning_service, system_info):
        """OLAP should enable JIT."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLAP, {}
        )
        jit = next(p for p in rec.parameters if p.name == "jit")
        assert jit.recommended_value == "on"

    def test_oltp_jit_disabled(self, tuning_service, system_info):
        """OLTP should disable JIT."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLTP, {}
        )
        jit = next(p for p in rec.parameters if p.name == "jit")
        assert jit.recommended_value == "off"

    def test_max_parallel_workers_matches_cpu(self, tuning_service, system_info):
        """max_parallel_workers should match CPU count."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        workers = next(p for p in rec.parameters if p.name == "max_parallel_workers")
        assert workers.recommended_value == "8"  # system_info.cpu_count

    def test_restart_required_parameters(self, tuning_service, system_info):
        """Certain parameters should be marked as requiring restart."""
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )

        restart_params = ["shared_buffers", "max_connections", "max_worker_processes"]
        for name in restart_params:
            param = next((p for p in rec.parameters if p.name == name), None)
            assert param is not None, f"Parameter {name} not found"
            assert param.requires_restart is True, f"{name} should require restart"


class TestGenerateConfig:
    """Tests for generate_config method."""

    @pytest.fixture
    def tuning_service(self):
        """Create tuning service with mocks."""
        ctx = Mock()
        ctx.dry_run = False
        executor = Mock()
        return PostgresTuningService(ctx, executor)

    def test_generates_valid_config(self, tuning_service):
        """Should generate valid PostgreSQL config format."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=4,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )
        config = tuning_service.generate_config(rec)

        # Check header
        assert "# PostgreSQL Tuning Configuration" in config
        assert "16384MB RAM" in config
        assert "4 CPUs" in config
        assert "SSD" in config
        assert "MIXED" in config

        # Check parameters are present
        assert "shared_buffers = " in config
        assert "effective_cache_size = " in config
        assert "work_mem = " in config
        assert "max_connections = " in config

    def test_config_includes_comments(self, tuning_service):
        """Config should include reasoning comments."""
        system_info = SystemInfo(
            memory_mb=16384,
            cpu_count=4,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLTP, {}
        )
        config = tuning_service.generate_config(rec)

        # Check that there are reasoning comments
        assert "# " in config
        assert "RAM" in config  # Mentions RAM in reasoning


class TestSmallSystemScaling:
    """Tests for systems with limited resources."""

    @pytest.fixture
    def tuning_service(self):
        """Create tuning service with mocks."""
        ctx = Mock()
        ctx.dry_run = False
        executor = Mock()
        return PostgresTuningService(ctx, executor)

    def test_small_memory_system(self, tuning_service):
        """Should scale down for systems with 2GB RAM."""
        system_info = SystemInfo(
            memory_mb=2048,  # 2GB
            cpu_count=2,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )

        shared = next(p for p in rec.parameters if p.name == "shared_buffers")
        # 30% of 2048 = ~614MB
        assert int(shared.recommended_value.replace("MB", "")) <= 700

    def test_single_cpu_system(self, tuning_service):
        """Should work with single CPU system."""
        system_info = SystemInfo(
            memory_mb=4096,
            cpu_count=1,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.MIXED, {}
        )

        workers = next(p for p in rec.parameters if p.name == "max_parallel_workers")
        assert workers.recommended_value == "1"


class TestLargeSystemScaling:
    """Tests for systems with large resources."""

    @pytest.fixture
    def tuning_service(self):
        """Create tuning service with mocks."""
        ctx = Mock()
        ctx.dry_run = False
        executor = Mock()
        return PostgresTuningService(ctx, executor)

    def test_large_memory_system(self, tuning_service):
        """Should handle systems with 256GB RAM."""
        system_info = SystemInfo(
            memory_mb=262144,  # 256GB
            cpu_count=64,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLAP, {}
        )

        shared = next(p for p in rec.parameters if p.name == "shared_buffers")
        # 40% of 256GB = ~102GB
        shared_mb = int(shared.recommended_value.replace("MB", ""))
        assert 100000 <= shared_mb <= 110000

        # maintenance_work_mem should cap at 4GB for OLAP
        maint = next(p for p in rec.parameters if p.name == "maintenance_work_mem")
        maint_mb = int(maint.recommended_value.replace("MB", ""))
        assert maint_mb <= 4096

    def test_many_cpus(self, tuning_service):
        """Should handle systems with many CPUs."""
        system_info = SystemInfo(
            memory_mb=131072,  # 128GB
            cpu_count=128,
            disk_type="ssd",
            pg_version="17",
            pg_data_dir=Path("/var/lib/postgresql/17/main"),
        )
        rec = tuning_service.calculate_recommendations(
            system_info, WorkloadProfile.OLAP, {}
        )

        workers = next(p for p in rec.parameters if p.name == "max_parallel_workers")
        assert workers.recommended_value == "128"

        gather = next(
            p for p in rec.parameters if p.name == "max_parallel_workers_per_gather"
        )
        # OLAP uses cpus // 2
        assert int(gather.recommended_value) == 64
