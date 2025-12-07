"""PostgreSQL tuning service.

Provides:
- System resource detection (CPU, memory, disk type)
- Workload-based tuning recommendations
- Configuration comparison and generation
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sm.core.context import ExecutionContext
from sm.core.executor import CommandExecutor


class WorkloadProfile(Enum):
    """PostgreSQL workload profiles."""

    OLTP = "oltp"
    OLAP = "olap"
    MIXED = "mixed"

    @property
    def description(self) -> str:
        """Human-readable description of the workload."""
        descriptions = {
            "oltp": "High concurrency, fast transactions (web applications)",
            "olap": "Complex queries, large datasets (analytics/reporting)",
            "mixed": "Balanced workload (general purpose)",
        }
        return descriptions[self.value]


@dataclass
class SystemInfo:
    """Detected system resources."""

    memory_mb: int
    cpu_count: int
    disk_type: str  # "ssd" or "hdd"
    pg_version: str
    pg_data_dir: Path


# Pre-compiled regex for memory unit parsing (used in value normalization)
_MEMORY_PATTERN = re.compile(r"^(\d+)\s*(kb|mb|gb|tb)?$", re.IGNORECASE)


# =============================================================================
# Pool Sizing Constants (shared between PostgreSQL and PgBouncer tuning)
# =============================================================================

# Pool utilization: what percentage of PostgreSQL's available connections to use
# OLTP: aggressive pooling (80%) - short transactions, high throughput
# OLAP: conservative (60%) - long queries, fewer connections needed
# MIXED: balanced (70%)
POOL_UTILIZATION_PCT = {"oltp": 0.80, "olap": 0.60, "mixed": 0.70}

# Multiplex ratio: how many client connections per server connection
# OLTP: high multiplexing (20x) - many short transactions share connections
# OLAP: low multiplexing (5x) - long queries hold connections
# MIXED: moderate (10x)
MULTIPLEX_RATIO = {"oltp": 20, "olap": 5, "mixed": 10}

# Server idle timeout (seconds): how long before recycling idle connections
IDLE_TIMEOUT_SECONDS = {"oltp": 300, "olap": 600, "mixed": 300}

# Reserved connections for admin/superuser access
RESERVED_FOR_ADMIN = 5


@dataclass
class TuningParameter:
    """A single tuning parameter with metadata."""

    name: str
    current_value: str | None
    recommended_value: str
    unit: str
    reason: str
    requires_restart: bool
    changed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Determine if value has changed."""
        self.changed = self._values_differ()

    def _values_differ(self) -> bool:
        """Compare current and recommended values, handling unit differences."""
        if self.current_value is None:
            return True

        current = self._normalize_value(self.current_value)
        recommended = self._normalize_value(self.recommended_value)
        return current != recommended

    def _normalize_value(self, value: str) -> str:
        """Normalize a PostgreSQL config value for comparison."""
        value = value.strip().lower()

        # Handle boolean values
        if value in ("on", "true", "yes", "1"):
            return "on"
        if value in ("off", "false", "no", "0"):
            return "off"

        # Handle memory units (convert to MB for comparison)
        match = _MEMORY_PATTERN.match(value)
        if match:
            num = int(match.group(1))
            unit = (match.group(2) or "").lower()
            if unit == "kb":
                return str(num // 1024)
            elif unit == "gb":
                return str(num * 1024)
            elif unit == "tb":
                return str(num * 1024 * 1024)
            else:
                return str(num)

        return value


@dataclass
class PgBouncerParameter:
    """A single PgBouncer tuning parameter with metadata."""

    name: str
    current_value: str | None
    recommended_value: str
    reason: str
    requires_reload: bool = True  # PgBouncer uses SIGHUP reload
    changed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Determine if value has changed."""
        if self.current_value is None:
            self.changed = True
        else:
            self.changed = str(self.current_value).strip() != str(self.recommended_value).strip()


@dataclass
class ConnectionStackRecommendation:
    """Unified recommendation for PostgreSQL + PgBouncer connection stack."""

    # PostgreSQL settings
    pg_max_connections: int
    pg_superuser_reserved: int = 5

    # PgBouncer settings
    pgb_default_pool_size: int = 20
    pgb_min_pool_size: int = 5
    pgb_reserve_pool_size: int = 5
    pgb_max_client_conn: int = 1000
    pgb_pool_mode: str = "transaction"
    pgb_server_idle_timeout: int = 300

    # Context
    expected_connections: int | None = None
    workload: str = "mixed"

    @property
    def effective_pg_connections(self) -> int:
        """Connections available for PgBouncer."""
        return self.pg_max_connections - self.pg_superuser_reserved

    @property
    def multiplex_ratio(self) -> float:
        """Client to server connection ratio."""
        if self.pgb_default_pool_size == 0:
            return 0.0
        return self.pgb_max_client_conn / self.pgb_default_pool_size

    @property
    def utilization_ratio(self) -> float:
        """How much of PostgreSQL capacity is used by pool."""
        if self.effective_pg_connections == 0:
            return 0.0
        return self.pgb_default_pool_size / self.effective_pg_connections

    @property
    def contention_ratio(self) -> float:
        """Expected connections to pool size ratio (lower is better)."""
        if self.pgb_default_pool_size == 0:
            return float("inf")
        if self.expected_connections:
            return self.expected_connections / self.pgb_default_pool_size
        return self.pgb_max_client_conn / self.pgb_default_pool_size


@dataclass
class TuningRecommendation:
    """Complete tuning recommendation."""

    system_info: SystemInfo
    workload_profile: WorkloadProfile
    parameters: list[TuningParameter] = field(default_factory=list)

    @property
    def changed_parameters(self) -> list[TuningParameter]:
        """Get only parameters that differ from current config."""
        return [p for p in self.parameters if p.changed]

    @property
    def has_restart_required(self) -> bool:
        """Check if any changed parameter requires restart."""
        return any(p.requires_restart and p.changed for p in self.parameters)


class PostgresTuningService:
    """PostgreSQL tuning calculator and system detector.

    Provides:
    - System resource detection (CPU, RAM, disk type)
    - Workload-based tuning recommendations
    - Current configuration reading
    - Config file generation
    """

    # Parameters that require PostgreSQL restart
    RESTART_REQUIRED = frozenset({
        "shared_buffers",
        "max_connections",
        "max_worker_processes",
        "max_parallel_workers",
        "wal_buffers",
        "huge_pages",
    })

    # All tunable parameters we track
    TUNABLE_PARAMETERS = [
        "shared_buffers",
        "effective_cache_size",
        "work_mem",
        "maintenance_work_mem",
        "wal_buffers",
        "max_connections",
        "max_worker_processes",
        "max_parallel_workers",
        "max_parallel_workers_per_gather",
        "max_parallel_maintenance_workers",
        "random_page_cost",
        "effective_io_concurrency",
        "seq_page_cost",
        "checkpoint_completion_target",
        "min_wal_size",
        "max_wal_size",
        "default_statistics_target",
        "jit",
    ]

    def __init__(self, ctx: ExecutionContext, executor: CommandExecutor) -> None:
        """Initialize tuning service.

        Args:
            ctx: Execution context
            executor: Command executor
        """
        self.ctx = ctx
        self.executor = executor

    def detect_system_info(self, pg_version: str) -> SystemInfo:
        """Detect all system resources.

        Args:
            pg_version: PostgreSQL version string

        Returns:
            SystemInfo with detected resources
        """
        pg_data_dir = self._get_pg_data_dir(pg_version)
        return SystemInfo(
            memory_mb=self._get_memory_mb(),
            cpu_count=self._get_cpu_count(),
            disk_type=self._detect_disk_type(pg_data_dir),
            pg_version=pg_version,
            pg_data_dir=pg_data_dir,
        )

    def _get_memory_mb(self) -> int:
        """Get total system memory in MB from /proc/meminfo."""
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        # Format: "MemTotal:     16384000 kB"
                        parts = line.split()
                        return int(parts[1]) // 1024
        except (OSError, ValueError, IndexError):
            pass
        return 4096  # Default to 4GB

    def _get_cpu_count(self) -> int:
        """Get number of CPU cores."""
        try:
            count = os.cpu_count()
            return count if count and count > 0 else 4
        except Exception:
            return 4

    def _get_pg_data_dir(self, pg_version: str) -> Path:
        """Get PostgreSQL data directory.

        Args:
            pg_version: PostgreSQL version

        Returns:
            Path to data directory
        """
        return Path(f"/var/lib/postgresql/{pg_version}/main")

    def _detect_disk_type(self, pg_data_dir: Path) -> str:
        """Detect if PostgreSQL data is on SSD or HDD.

        Checks the rotational flag of the block device.

        Args:
            pg_data_dir: PostgreSQL data directory

        Returns:
            "ssd" or "hdd"
        """
        if self.ctx.dry_run:
            return "ssd"

        try:
            # Get device for data directory using df
            result = subprocess.run(
                ["df", "--output=source", str(pg_data_dir)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return "ssd"

            device = result.stdout.strip().split("\n")[-1]
            base_device = self._extract_base_device(device)

            if not base_device:
                return "ssd"

            # Check rotational flag
            # 0 = SSD (non-rotational), 1 = HDD (rotational)
            rotational_path = Path(f"/sys/block/{base_device}/queue/rotational")
            if rotational_path.exists():
                is_rotational = rotational_path.read_text().strip() == "1"
                return "hdd" if is_rotational else "ssd"

        except Exception:
            pass

        return "ssd"  # Default to SSD (more conservative settings)

    def _extract_base_device(self, device: str) -> str | None:
        """Extract base block device name from device path.

        Handles:
        - /dev/sda1 -> sda
        - /dev/nvme0n1p1 -> nvme0n1
        - /dev/vda1 -> vda
        - /dev/mapper/* -> None (would need dm-X lookup)

        Args:
            device: Device path

        Returns:
            Base device name or None
        """
        device = device.replace("/dev/", "")

        # Handle LVM/device mapper - skip for now
        if device.startswith("mapper/") or device.startswith("dm-"):
            return None

        # Handle NVMe: nvme0n1p1 -> nvme0n1
        nvme_match = re.match(r"(nvme\d+n\d+)", device)
        if nvme_match:
            return nvme_match.group(1)

        # Handle traditional: sda1 -> sda, vda1 -> vda
        trad_match = re.match(r"([a-z]+)", device)
        if trad_match:
            return trad_match.group(1)

        return None

    def _calculate_max_connections(
        self, memory_mb: int, workload: WorkloadProfile
    ) -> int:
        """Calculate optimal max_connections based on RAM and workload.

        Formula:
        - Reserve RAM for shared_buffers (workload-dependent %)
        - Use 50% of remaining RAM for connection overhead
        - Each connection uses ~5-15MB (work_mem, temp buffers, overhead)

        Args:
            memory_mb: Total system memory in MB
            workload: Target workload profile

        Returns:
            Recommended max_connections value
        """
        # shared_buffers percentage by workload
        shared_pct = {"oltp": 0.25, "olap": 0.40, "mixed": 0.30}[workload.value]

        # Available RAM for connections (excluding shared_buffers, using 50% of remainder)
        available_mb = memory_mb * (1 - shared_pct) * 0.5

        # Per-connection memory overhead by workload
        # OLTP: smaller work_mem, shorter transactions
        # OLAP: larger work_mem, complex queries
        per_conn_mb = {"oltp": 5, "olap": 15, "mixed": 8}[workload.value]

        # Calculate based on available memory
        calculated = int(available_mb / per_conn_mb)

        # Apply workload-specific bounds
        # OLTP: high concurrency needed (100-500)
        # OLAP: fewer long-running queries (30-100)
        # Mixed: balanced (50-300)
        bounds = {
            "oltp": (100, 500),
            "olap": (30, 100),
            "mixed": (50, 300),
        }
        min_conn, max_conn = bounds[workload.value]

        return max(min_conn, min(calculated, max_conn))

    def calculate_connection_stack(
        self,
        memory_mb: int,
        workload: WorkloadProfile,
        expected_connections: int | None = None,
    ) -> ConnectionStackRecommendation:
        """Calculate coordinated PostgreSQL + PgBouncer connection settings.

        This ensures PgBouncer pool settings are properly sized relative to
        PostgreSQL's max_connections, eliminating connection bottlenecks.

        Args:
            memory_mb: Total system memory in MB
            workload: Target workload profile
            expected_connections: Expected number of app connections

        Returns:
            ConnectionStackRecommendation with coordinated settings
        """
        # Calculate PostgreSQL max_connections
        pg_max_conn = self._calculate_max_connections(memory_mb, workload)
        available_for_pool = pg_max_conn - RESERVED_FOR_ADMIN

        # Pool utilization: use shared constants
        pool_pct = POOL_UTILIZATION_PCT[workload.value]
        default_pool_size = max(20, int(available_for_pool * pool_pct))

        # Multiplex ratio: use shared constants
        multiplex = MULTIPLEX_RATIO[workload.value]
        max_client_conn = default_pool_size * multiplex

        # Adjust for expected connections if provided
        if expected_connections:
            # Ensure we can handle at least 1.5x expected connections
            max_client_conn = max(max_client_conn, int(expected_connections * 1.5))

        # min_pool_size: keep 25% of pool ready for quick response
        min_pool_size = max(5, default_pool_size // 4)

        # reserve_pool_size: 20% emergency overflow
        reserve_pool_size = max(5, default_pool_size // 5)

        # Server idle timeout: use shared constants
        idle_timeout = IDLE_TIMEOUT_SECONDS[workload.value]

        return ConnectionStackRecommendation(
            pg_max_connections=pg_max_conn,
            pg_superuser_reserved=RESERVED_FOR_ADMIN,
            pgb_default_pool_size=default_pool_size,
            pgb_min_pool_size=min_pool_size,
            pgb_reserve_pool_size=reserve_pool_size,
            pgb_max_client_conn=max_client_conn,
            pgb_pool_mode="transaction",
            pgb_server_idle_timeout=idle_timeout,
            expected_connections=expected_connections,
            workload=workload.value,
        )

    def read_current_config(self, pg_version: str) -> dict[str, str]:
        """Read current PostgreSQL settings via a single pg_settings query.

        Uses a batched query to pg_settings instead of individual SHOW commands,
        reducing 18 database round-trips to 1.

        Note: This is a read-only operation, so it runs even in dry-run mode.
        This ensures the preview shows accurate current vs recommended comparisons.

        Args:
            pg_version: PostgreSQL version

        Returns:
            Dict of parameter name -> current value (converted to human-readable format)
        """
        # Note: We intentionally DO NOT skip in dry_run mode.
        # Reading current config is non-destructive and needed for accurate previews.

        settings = {}
        try:
            # Build single query for all parameters, including unit for proper conversion
            # Note: TUNABLE_PARAMETERS is a hardcoded constant, not user input
            params_list = "', '".join(self.TUNABLE_PARAMETERS)
            result = self.executor.run_sql(
                f"SELECT name, setting, unit FROM pg_settings WHERE name IN ('{params_list}')",  # noqa: S608
                as_user="postgres",
                check=False,
            )
            if result:
                for line in result.strip().split("\n"):
                    # Handle psql output format: "name|setting|unit"
                    if "|" in line:
                        parts = line.split("|")
                        if len(parts) >= 2:
                            name = parts[0].strip()
                            value = parts[1].strip()
                            unit = parts[2].strip() if len(parts) > 2 else ""
                            if name in self.TUNABLE_PARAMETERS:
                                # Convert to human-readable format for comparison
                                settings[name] = self._convert_pg_value(name, value, unit)
        except Exception:
            # Fallback to individual queries if batched query fails
            for param in self.TUNABLE_PARAMETERS:
                try:
                    result = self.executor.run_sql(
                        f"SHOW {param}",
                        as_user="postgres",
                        check=False,
                    )
                    if result and result.strip():
                        settings[param] = result.strip()
                except Exception:
                    pass

        return settings

    def _convert_pg_value(self, name: str, value: str, unit: str) -> str:
        """Convert PostgreSQL raw setting value to human-readable format.

        PostgreSQL stores memory values in various units (8kB pages, kB, etc.).
        This converts them to the same format used in recommendations (e.g., "954MB").

        Args:
            name: Parameter name
            value: Raw setting value from pg_settings
            unit: Unit from pg_settings (e.g., "8kB", "kB", "MB", "ms", "s", "min")

        Returns:
            Human-readable value string
        """
        # Non-numeric values (like "on", "off") - return as-is
        try:
            num_value = int(value)
        except ValueError:
            return value

        # Handle memory units - convert to MB for consistency with recommendations
        if unit == "8kB":
            # 8KB pages (shared_buffers, wal_buffers, effective_cache_size)
            mb_value = (num_value * 8) // 1024
            return f"{mb_value}MB"
        elif unit == "kB":
            # Kilobytes (work_mem, maintenance_work_mem)
            mb_value = num_value // 1024
            return f"{mb_value}MB"
        elif unit == "MB":
            # Already in MB (min_wal_size, max_wal_size)
            return f"{num_value}MB"
        elif unit == "GB":
            # Gigabytes
            return f"{num_value}GB"
        elif unit in ("", None):
            # No unit - return as-is (max_connections, worker counts, etc.)
            return str(num_value)
        else:
            # Other units (time, etc.) - return with unit suffix
            return f"{num_value}{unit}"

    def calculate_recommendations(
        self,
        system_info: SystemInfo,
        workload: WorkloadProfile,
        current_config: dict[str, str],
    ) -> TuningRecommendation:
        """Calculate recommended settings based on system and workload.

        Args:
            system_info: Detected system resources
            workload: Target workload profile
            current_config: Current PostgreSQL settings

        Returns:
            TuningRecommendation with all parameters
        """
        params: list[TuningParameter] = []

        memory = system_info.memory_mb
        cpus = system_info.cpu_count
        is_ssd = system_info.disk_type == "ssd"

        # === Memory Settings ===

        # shared_buffers: workload-dependent percentage of RAM
        shared_pct = {"oltp": 0.25, "olap": 0.40, "mixed": 0.30}[workload.value]
        shared_mb = int(memory * shared_pct)
        params.append(TuningParameter(
            name="shared_buffers",
            current_value=current_config.get("shared_buffers"),
            recommended_value=f"{shared_mb}MB",
            unit="MB",
            reason=f"{int(shared_pct * 100)}% of RAM for {workload.value.upper()} workload",
            requires_restart=True,
        ))

        # effective_cache_size: 75% of RAM (OS file system cache estimate)
        cache_mb = int(memory * 0.75)
        params.append(TuningParameter(
            name="effective_cache_size",
            current_value=current_config.get("effective_cache_size"),
            recommended_value=f"{cache_mb}MB",
            unit="MB",
            reason="75% of RAM - OS file system cache estimate",
            requires_restart=False,
        ))

        # work_mem: workload-dependent per-operation memory
        # OLAP needs more memory for complex sorts/hashes, even on small systems
        work_mem_values = {
            "oltp": 64,
            "olap": max(128, min(memory // 32, 1024)),  # At least 128MB, up to 1GB
            "mixed": 128,
        }
        work_mem = work_mem_values[workload.value]
        params.append(TuningParameter(
            name="work_mem",
            current_value=current_config.get("work_mem"),
            recommended_value=f"{work_mem}MB",
            unit="MB",
            reason=f"Per-operation memory for sorts/hashes ({workload.value.upper()})",
            requires_restart=False,
        ))

        # maintenance_work_mem: for VACUUM, CREATE INDEX, etc.
        if workload == WorkloadProfile.OLAP:
            maint_mem = min(memory // 4, 4096)  # Up to 4GB for OLAP
        else:
            maint_mem = min(memory // 8, 2048)  # Up to 2GB for others
        params.append(TuningParameter(
            name="maintenance_work_mem",
            current_value=current_config.get("maintenance_work_mem"),
            recommended_value=f"{maint_mem}MB",
            unit="MB",
            reason="Memory for VACUUM, CREATE INDEX, ALTER TABLE",
            requires_restart=False,
        ))

        # wal_buffers: auto or 64MB
        params.append(TuningParameter(
            name="wal_buffers",
            current_value=current_config.get("wal_buffers"),
            recommended_value="64MB",
            unit="MB",
            reason="WAL write buffer (auto-tuned from shared_buffers)",
            requires_restart=True,
        ))

        # === Parallel Query Settings (CPU-based) ===

        params.append(TuningParameter(
            name="max_worker_processes",
            current_value=current_config.get("max_worker_processes"),
            recommended_value=str(cpus),
            unit="",
            reason=f"Match CPU core count ({cpus})",
            requires_restart=True,
        ))

        params.append(TuningParameter(
            name="max_parallel_workers",
            current_value=current_config.get("max_parallel_workers"),
            recommended_value=str(cpus),
            unit="",
            reason=f"Match CPU core count ({cpus})",
            requires_restart=False,
        ))

        # max_parallel_workers_per_gather: workload-dependent
        parallel_per_gather = {
            "oltp": 2,
            "olap": max(2, cpus // 2),
            "mixed": min(4, cpus),
        }[workload.value]
        params.append(TuningParameter(
            name="max_parallel_workers_per_gather",
            current_value=current_config.get("max_parallel_workers_per_gather"),
            recommended_value=str(parallel_per_gather),
            unit="",
            reason=f"Parallel workers per query ({workload.value.upper()})",
            requires_restart=False,
        ))

        # max_parallel_maintenance_workers
        maint_workers = max(2, cpus // 4)
        params.append(TuningParameter(
            name="max_parallel_maintenance_workers",
            current_value=current_config.get("max_parallel_maintenance_workers"),
            recommended_value=str(maint_workers),
            unit="",
            reason="Parallel workers for maintenance operations",
            requires_restart=False,
        ))

        # === Disk I/O Settings (SSD vs HDD) ===

        random_reason = "SSD has near-sequential random access" if is_ssd else "HDD random I/O cost"
        params.append(TuningParameter(
            name="random_page_cost",
            current_value=current_config.get("random_page_cost"),
            recommended_value="1.1" if is_ssd else "4.0",
            unit="",
            reason=random_reason,
            requires_restart=False,
        ))

        params.append(TuningParameter(
            name="effective_io_concurrency",
            current_value=current_config.get("effective_io_concurrency"),
            recommended_value="200" if is_ssd else "2",
            unit="",
            reason="SSD handles parallel I/O well" if is_ssd else "HDD limited parallel I/O",
            requires_restart=False,
        ))

        # === Connection Settings ===

        # Use adaptive calculation based on RAM instead of fixed values
        max_conn = self._calculate_max_connections(memory, workload)
        conn_reason = (
            f"Adaptive: {memory}MB RAM, {workload.value.upper()} "
            f"({max_conn} = optimal for {workload.description})"
        )
        params.append(TuningParameter(
            name="max_connections",
            current_value=current_config.get("max_connections"),
            recommended_value=str(max_conn),
            unit="",
            reason=conn_reason,
            requires_restart=True,
        ))

        # === WAL Settings ===

        min_wal = {"oltp": "1GB", "olap": "2GB", "mixed": "1GB"}[workload.value]
        max_wal = {"oltp": "4GB", "olap": "8GB", "mixed": "4GB"}[workload.value]

        params.append(TuningParameter(
            name="min_wal_size",
            current_value=current_config.get("min_wal_size"),
            recommended_value=min_wal,
            unit="",
            reason="WAL file retention minimum",
            requires_restart=False,
        ))

        params.append(TuningParameter(
            name="max_wal_size",
            current_value=current_config.get("max_wal_size"),
            recommended_value=max_wal,
            unit="",
            reason=f"WAL headroom for {workload.value.upper()} workload",
            requires_restart=False,
        ))

        params.append(TuningParameter(
            name="checkpoint_completion_target",
            current_value=current_config.get("checkpoint_completion_target"),
            recommended_value="0.9",
            unit="",
            reason="Spread checkpoint I/O over time",
            requires_restart=False,
        ))

        # === Planner Settings ===

        stats_target = {"oltp": 100, "olap": 500, "mixed": 200}[workload.value]
        params.append(TuningParameter(
            name="default_statistics_target",
            current_value=current_config.get("default_statistics_target"),
            recommended_value=str(stats_target),
            unit="",
            reason="Better statistics for complex OLAP queries" if workload == WorkloadProfile.OLAP
            else "Standard statistics collection",
            requires_restart=False,
        ))

        # JIT: beneficial for OLAP, overhead for OLTP
        jit_value = "on" if workload == WorkloadProfile.OLAP else "off"
        params.append(TuningParameter(
            name="jit",
            current_value=current_config.get("jit"),
            recommended_value=jit_value,
            unit="",
            reason="JIT compilation helps complex OLAP queries" if workload == WorkloadProfile.OLAP
            else "JIT overhead not beneficial for OLTP",
            requires_restart=False,
        ))

        return TuningRecommendation(
            system_info=system_info,
            workload_profile=workload,
            parameters=params,
        )

    def generate_config(self, recommendation: TuningRecommendation) -> str:
        """Generate PostgreSQL config file content.

        Args:
            recommendation: Tuning recommendation

        Returns:
            Config file content as string
        """
        sep = "# " + "=" * 74
        lines = [
            "# PostgreSQL Tuning Configuration",
            "# Generated by: sm postgres optimize",
            f"# System: {recommendation.system_info.memory_mb}MB RAM, "
            f"{recommendation.system_info.cpu_count} CPUs, "
            f"{recommendation.system_info.disk_type.upper()}",
            f"# Workload: {recommendation.workload_profile.value.upper()} - "
            f"{recommendation.workload_profile.description}",
            "",
            sep,
            "# Memory Settings",
            sep,
        ]

        # Group parameters by category
        memory_params = ["shared_buffers", "effective_cache_size", "work_mem",
                         "maintenance_work_mem", "wal_buffers"]
        parallel_params = ["max_worker_processes", "max_parallel_workers",
                           "max_parallel_workers_per_gather", "max_parallel_maintenance_workers"]
        disk_params = ["random_page_cost", "effective_io_concurrency"]
        conn_params = ["max_connections"]
        wal_params = ["min_wal_size", "max_wal_size", "checkpoint_completion_target"]
        planner_params = ["default_statistics_target", "jit"]

        params_by_name = {p.name: p for p in recommendation.parameters}

        # Memory settings
        for name in memory_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        # Parallel settings
        lines.append(sep)
        lines.append("# Parallel Query Settings")
        lines.append(sep)
        for name in parallel_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        # Disk I/O settings
        lines.append(sep)
        lines.append(f"# Disk I/O Settings ({recommendation.system_info.disk_type.upper()})")
        lines.append(sep)
        for name in disk_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        # Connection settings
        lines.append(sep)
        lines.append("# Connection Settings")
        lines.append(sep)
        for name in conn_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        # WAL settings
        lines.append(sep)
        lines.append("# WAL Settings")
        lines.append(sep)
        for name in wal_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        # Planner settings
        lines.append(sep)
        lines.append("# Planner Settings")
        lines.append(sep)
        for name in planner_params:
            if name in params_by_name:
                p = params_by_name[name]
                lines.append(f"# {p.reason}")
                lines.append(f"{p.name} = {p.recommended_value}")
                lines.append("")

        return "\n".join(lines)
