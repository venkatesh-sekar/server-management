"""Firewall service definitions and source aliases.

Provides user-friendly service names and plain English source aliases
for simplified firewall management.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

from sm.services.iptables import Protocol
from sm.services.network import DEFAULT_INTERNAL_CIDRS, detect_internal_networks


@dataclass
class PortSpec:
    """Specification for a single port."""

    port: int
    protocol: Protocol
    description: str


@dataclass
class ServiceDefinition:
    """Definition of a network service."""

    name: str
    display_name: str
    description: str
    ports: list[PortSpec]
    category: str
    default_source: str = "anywhere"
    warning: Optional[str] = None
    always_allowed: bool = False
    aliases: list[str] = field(default_factory=list)


@dataclass
class SourceDefinition:
    """Definition of a source alias."""

    name: str
    display_name: str
    description: str
    cidr: Optional[str] = None  # None means dynamic resolution
    warning: Optional[str] = None
    resolver: Optional[Callable[[], list[str]]] = None


# =============================================================================
# Service Registry
# =============================================================================

SERVICES: dict[str, ServiceDefinition] = {
    # Web services
    "web": ServiceDefinition(
        name="web",
        display_name="Web Server",
        description="HTTP and HTTPS traffic for websites and APIs",
        ports=[
            PortSpec(80, Protocol.TCP, "HTTP"),
            PortSpec(443, Protocol.TCP, "HTTPS"),
        ],
        category="web",
        default_source="anywhere",
        aliases=["website", "http-https"],
    ),
    "http": ServiceDefinition(
        name="http",
        display_name="HTTP",
        description="Unencrypted web traffic (port 80)",
        ports=[PortSpec(80, Protocol.TCP, "HTTP")],
        category="web",
        default_source="anywhere",
    ),
    "https": ServiceDefinition(
        name="https",
        display_name="HTTPS",
        description="Encrypted web traffic (port 443)",
        ports=[PortSpec(443, Protocol.TCP, "HTTPS")],
        category="web",
        default_source="anywhere",
        aliases=["ssl", "tls"],
    ),
    # Database services
    "postgres": ServiceDefinition(
        name="postgres",
        display_name="PostgreSQL",
        description="PostgreSQL database server",
        ports=[PortSpec(5432, Protocol.TCP, "PostgreSQL")],
        category="database",
        default_source="local-network",
        warning="Databases should typically only be accessible from trusted networks",
        aliases=["postgresql", "pg", "pgsql"],
    ),
    "pgbouncer": ServiceDefinition(
        name="pgbouncer",
        display_name="PgBouncer",
        description="PostgreSQL connection pooler",
        ports=[PortSpec(6432, Protocol.TCP, "PgBouncer")],
        category="database",
        default_source="local-network",
        warning="Connection poolers should typically only be accessible from trusted networks",
    ),
    "mysql": ServiceDefinition(
        name="mysql",
        display_name="MySQL",
        description="MySQL/MariaDB database server",
        ports=[PortSpec(3306, Protocol.TCP, "MySQL")],
        category="database",
        default_source="local-network",
        warning="Databases should typically only be accessible from trusted networks",
        aliases=["mariadb"],
    ),
    "redis": ServiceDefinition(
        name="redis",
        display_name="Redis",
        description="Redis cache/database server",
        ports=[PortSpec(6379, Protocol.TCP, "Redis")],
        category="database",
        default_source="local-network",
        warning="Redis has no authentication by default - restrict access carefully",
    ),
    "mongodb": ServiceDefinition(
        name="mongodb",
        display_name="MongoDB",
        description="MongoDB database server",
        ports=[PortSpec(27017, Protocol.TCP, "MongoDB")],
        category="database",
        default_source="local-network",
        warning="Databases should typically only be accessible from trusted networks",
        aliases=["mongo"],
    ),
    # System services
    "ssh": ServiceDefinition(
        name="ssh",
        display_name="SSH",
        description="Secure Shell remote access",
        ports=[PortSpec(22, Protocol.TCP, "SSH")],
        category="system",
        default_source="anywhere",
        always_allowed=True,  # Cannot be blocked
    ),
    "dns": ServiceDefinition(
        name="dns",
        display_name="DNS",
        description="Domain Name System server",
        ports=[
            PortSpec(53, Protocol.TCP, "DNS TCP"),
            PortSpec(53, Protocol.UDP, "DNS UDP"),
        ],
        category="system",
        default_source="anywhere",
    ),
    "ntp": ServiceDefinition(
        name="ntp",
        display_name="NTP",
        description="Network Time Protocol server",
        ports=[PortSpec(123, Protocol.UDP, "NTP")],
        category="system",
        default_source="local-network",
    ),
    # Docker/Container services
    "docker-swarm": ServiceDefinition(
        name="docker-swarm",
        display_name="Docker Swarm",
        description="Docker Swarm cluster communication",
        ports=[
            PortSpec(2377, Protocol.TCP, "Swarm management"),
            PortSpec(7946, Protocol.TCP, "Node discovery TCP"),
            PortSpec(7946, Protocol.UDP, "Node discovery UDP"),
            PortSpec(4789, Protocol.UDP, "Overlay network"),
        ],
        category="containers",
        default_source="local-network",
        aliases=["swarm"],
    ),
    "docker-api": ServiceDefinition(
        name="docker-api",
        display_name="Docker API",
        description="Docker daemon remote API",
        ports=[PortSpec(2375, Protocol.TCP, "Docker API")],
        category="containers",
        default_source="this-machine",
        warning="DANGER: Never expose Docker API to the internet! Use TLS (2376) with certificates.",
    ),
    # Mail services
    "mail": ServiceDefinition(
        name="mail",
        display_name="Mail Server",
        description="Email server (SMTP, IMAP, secure variants)",
        ports=[
            PortSpec(25, Protocol.TCP, "SMTP"),
            PortSpec(465, Protocol.TCP, "SMTPS"),
            PortSpec(587, Protocol.TCP, "Submission"),
            PortSpec(143, Protocol.TCP, "IMAP"),
            PortSpec(993, Protocol.TCP, "IMAPS"),
        ],
        category="mail",
        default_source="anywhere",
        aliases=["email", "smtp"],
    ),
    "smtp": ServiceDefinition(
        name="smtp",
        display_name="SMTP",
        description="Simple Mail Transfer Protocol",
        ports=[
            PortSpec(25, Protocol.TCP, "SMTP"),
            PortSpec(587, Protocol.TCP, "Submission"),
        ],
        category="mail",
        default_source="anywhere",
    ),
    # Monitoring services
    "prometheus": ServiceDefinition(
        name="prometheus",
        display_name="Prometheus",
        description="Prometheus metrics server",
        ports=[PortSpec(9090, Protocol.TCP, "Prometheus")],
        category="monitoring",
        default_source="local-network",
    ),
    "grafana": ServiceDefinition(
        name="grafana",
        display_name="Grafana",
        description="Grafana dashboard server",
        ports=[PortSpec(3000, Protocol.TCP, "Grafana")],
        category="monitoring",
        default_source="local-network",
    ),
    "node-exporter": ServiceDefinition(
        name="node-exporter",
        display_name="Node Exporter",
        description="Prometheus node exporter",
        ports=[PortSpec(9100, Protocol.TCP, "Node Exporter")],
        category="monitoring",
        default_source="local-network",
    ),
}

# Build alias lookup
_ALIAS_TO_SERVICE: dict[str, str] = {}
for service_name, service_def in SERVICES.items():
    for alias in service_def.aliases:
        _ALIAS_TO_SERVICE[alias] = service_name


# =============================================================================
# Source Aliases
# =============================================================================

SOURCE_ALIASES: dict[str, SourceDefinition] = {
    "anywhere": SourceDefinition(
        name="anywhere",
        display_name="Anywhere",
        description="Any IP address on the internet",
        cidr="0.0.0.0/0",
        warning="This allows access from anywhere on the internet",
    ),
    "local-network": SourceDefinition(
        name="local-network",
        display_name="Local Network",
        description="Private/internal networks only (10.x, 192.168.x, 172.16-31.x)",
        cidr=None,  # Dynamically resolved
        resolver=lambda: detect_internal_networks() or DEFAULT_INTERNAL_CIDRS,
    ),
    "this-machine": SourceDefinition(
        name="this-machine",
        display_name="This Machine",
        description="Only this server itself (localhost)",
        cidr="127.0.0.1",
    ),
}

# Aliases for source names
_SOURCE_ALIASES: dict[str, str] = {
    "any": "anywhere",
    "all": "anywhere",
    "internet": "anywhere",
    "local": "local-network",
    "internal": "local-network",
    "private": "local-network",
    "localhost": "this-machine",
    "loopback": "this-machine",
    "self": "this-machine",
}


# =============================================================================
# Resolution Functions
# =============================================================================


def resolve_service(name: str) -> Optional[ServiceDefinition]:
    """Resolve a service name or alias to its definition.

    Args:
        name: Service name, alias, or port number as string

    Returns:
        ServiceDefinition if found, None otherwise
    """
    name_lower = name.lower().strip()

    # Direct lookup
    if name_lower in SERVICES:
        return SERVICES[name_lower]

    # Alias lookup
    if name_lower in _ALIAS_TO_SERVICE:
        return SERVICES[_ALIAS_TO_SERVICE[name_lower]]

    return None


def resolve_source(source: str) -> list[str]:
    """Resolve a source string to CIDR notation(s).

    Args:
        source: Plain English name, alias, or CIDR notation

    Returns:
        List of CIDR strings (may be multiple for local-network)

    Examples:
        >>> resolve_source("anywhere")
        ["0.0.0.0/0"]
        >>> resolve_source("local-network")
        ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        >>> resolve_source("10.0.0.5")
        ["10.0.0.5"]
    """
    source_lower = source.lower().strip()

    # Check direct source alias
    if source_lower in SOURCE_ALIASES:
        source_def = SOURCE_ALIASES[source_lower]
        if source_def.resolver:
            return source_def.resolver()
        return [source_def.cidr] if source_def.cidr else ["0.0.0.0/0"]

    # Check source alias mappings
    if source_lower in _SOURCE_ALIASES:
        canonical = _SOURCE_ALIASES[source_lower]
        return resolve_source(canonical)

    # Assume it's a CIDR or IP - return as-is
    # Validation happens later in the iptables service
    return [source]


def get_source_definition(source: str) -> Optional[SourceDefinition]:
    """Get the source definition for a source name.

    Args:
        source: Source name or alias

    Returns:
        SourceDefinition if it's a known alias, None for raw CIDR
    """
    source_lower = source.lower().strip()

    if source_lower in SOURCE_ALIASES:
        return SOURCE_ALIASES[source_lower]

    if source_lower in _SOURCE_ALIASES:
        canonical = _SOURCE_ALIASES[source_lower]
        return SOURCE_ALIASES[canonical]

    return None


def is_port_number(value: str) -> bool:
    """Check if a string is a valid port number.

    Args:
        value: String to check

    Returns:
        True if it's a valid port number (1-65535)
    """
    try:
        port = int(value)
        return 1 <= port <= 65535
    except ValueError:
        return False


def get_service_by_port(port: int, protocol: Protocol = Protocol.TCP) -> Optional[ServiceDefinition]:
    """Find a service definition by port number.

    Args:
        port: Port number to look up
        protocol: Protocol to match

    Returns:
        ServiceDefinition if a matching service is found
    """
    for service in SERVICES.values():
        for port_spec in service.ports:
            if port_spec.port == port and port_spec.protocol == protocol:
                return service
    return None


def get_services_by_category(category: str) -> list[ServiceDefinition]:
    """Get all services in a category.

    Args:
        category: Category name (web, database, system, etc.)

    Returns:
        List of services in that category
    """
    return [s for s in SERVICES.values() if s.category == category]


def list_all_services() -> list[ServiceDefinition]:
    """Get all available services.

    Returns:
        List of all service definitions
    """
    return list(SERVICES.values())


def list_all_sources() -> list[SourceDefinition]:
    """Get all available source aliases.

    Returns:
        List of all source definitions
    """
    return list(SOURCE_ALIASES.values())


def format_source_for_display(source: str) -> str:
    """Format a source CIDR for human-friendly display.

    Args:
        source: CIDR notation or source alias

    Returns:
        Human-readable description
    """
    # Check if it matches a known source
    if source == "0.0.0.0/0":
        return "Anywhere"
    if source == "127.0.0.1" or source == "127.0.0.0/8":
        return "This Machine"

    # Check if it's a private network
    private_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168."]
    for prefix in private_prefixes:
        if source.startswith(prefix):
            return f"Local ({source})"

    return source
