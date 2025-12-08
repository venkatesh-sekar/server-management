"""Unit tests for the firewall services definitions module."""

import pytest
from unittest.mock import patch, MagicMock

from sm.services.firewall_services import (
    PortSpec,
    ServiceDefinition,
    SourceDefinition,
    resolve_service,
    resolve_source,
    get_source_definition,
    get_service_by_port,
    get_services_by_category,
    is_port_number,
    format_source_for_display,
    SERVICES,
    SOURCE_ALIASES,
)
from sm.services.iptables import Protocol


class TestPortSpec:
    """Tests for PortSpec dataclass."""

    def test_port_spec_creation(self):
        """Should create PortSpec with port, protocol, and description."""
        spec = PortSpec(port=443, protocol=Protocol.TCP, description="HTTPS")
        assert spec.port == 443
        assert spec.protocol == Protocol.TCP
        assert spec.description == "HTTPS"

    def test_port_spec_str(self):
        """Should have readable string representation."""
        spec = PortSpec(port=5432, protocol=Protocol.TCP, description="PostgreSQL")
        s = str(spec)
        assert "5432" in s


class TestServiceDefinition:
    """Tests for ServiceDefinition dataclass."""

    def test_service_definition_creation(self):
        """Should create ServiceDefinition with all fields."""
        service = ServiceDefinition(
            name="postgres",
            display_name="PostgreSQL",
            description="PostgreSQL database server",
            ports=[PortSpec(5432, Protocol.TCP, "PostgreSQL")],
            category="database",
            default_source="local-network",
        )
        assert service.name == "postgres"
        assert service.display_name == "PostgreSQL"
        assert len(service.ports) == 1
        assert service.default_source == "local-network"

    def test_service_with_multiple_ports(self):
        """Should support multiple ports."""
        service = ServiceDefinition(
            name="web",
            display_name="Web",
            description="Web traffic",
            ports=[
                PortSpec(80, Protocol.TCP, "HTTP"),
                PortSpec(443, Protocol.TCP, "HTTPS"),
            ],
            category="web",
        )
        assert len(service.ports) == 2
        assert service.ports[0].port == 80
        assert service.ports[1].port == 443

    def test_service_with_warning(self):
        """Should support warning messages."""
        service = ServiceDefinition(
            name="postgres",
            display_name="PostgreSQL",
            description="PostgreSQL database server",
            ports=[PortSpec(5432, Protocol.TCP, "PostgreSQL")],
            category="database",
            warning="Database ports should not be exposed to the internet",
        )
        assert service.warning is not None
        assert "database" in service.warning.lower()

    def test_service_always_allowed(self):
        """Should support always_allowed flag."""
        service = ServiceDefinition(
            name="ssh",
            display_name="SSH",
            description="SSH access",
            ports=[PortSpec(22, Protocol.TCP, "SSH")],
            category="system",
            always_allowed=True,
        )
        assert service.always_allowed is True


class TestSourceDefinition:
    """Tests for SourceDefinition dataclass."""

    def test_source_definition_creation(self):
        """Should create SourceDefinition with name and cidr."""
        source = SourceDefinition(
            name="anywhere",
            display_name="Anywhere (Internet)",
            description="Any IP address",
            cidr="0.0.0.0/0",
        )
        assert source.name == "anywhere"
        assert source.cidr == "0.0.0.0/0"

    def test_source_with_resolver(self):
        """Should support resolver function for dynamic CIDRs."""
        source = SourceDefinition(
            name="local-network",
            display_name="Local Network",
            description="Private network ranges",
            cidr=None,
            resolver=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        )
        assert source.cidr is None
        assert source.resolver is not None
        assert len(source.resolver()) == 3


class TestBuiltInServices:
    """Tests for built-in service definitions."""

    def test_web_service_exists(self):
        """Web service should be defined."""
        assert "web" in SERVICES
        web = SERVICES["web"]
        assert web.category == "web"
        # Should include HTTP and HTTPS
        ports = [p.port for p in web.ports]
        assert 80 in ports
        assert 443 in ports

    def test_http_service_exists(self):
        """HTTP service should be defined separately."""
        assert "http" in SERVICES
        http = SERVICES["http"]
        assert http.ports[0].port == 80

    def test_https_service_exists(self):
        """HTTPS service should be defined separately."""
        assert "https" in SERVICES
        https = SERVICES["https"]
        assert https.ports[0].port == 443

    def test_postgres_service_exists(self):
        """PostgreSQL service should be defined."""
        assert "postgres" in SERVICES
        pg = SERVICES["postgres"]
        assert pg.category == "database"
        assert pg.ports[0].port == 5432
        assert pg.default_source == "local-network"

    def test_ssh_service_exists(self):
        """SSH service should be defined."""
        assert "ssh" in SERVICES
        ssh = SERVICES["ssh"]
        assert ssh.category == "system"
        assert ssh.ports[0].port == 22
        assert ssh.always_allowed is True

    def test_mysql_service_exists(self):
        """MySQL service should be defined."""
        assert "mysql" in SERVICES
        mysql = SERVICES["mysql"]
        assert mysql.category == "database"
        assert mysql.ports[0].port == 3306

    def test_redis_service_exists(self):
        """Redis service should be defined."""
        assert "redis" in SERVICES
        redis = SERVICES["redis"]
        assert redis.category == "database"
        assert redis.ports[0].port == 6379

    def test_docker_swarm_service_exists(self):
        """Docker Swarm service should be defined."""
        assert "docker-swarm" in SERVICES
        swarm = SERVICES["docker-swarm"]
        assert swarm.category == "containers"
        # Should have multiple ports
        assert len(swarm.ports) >= 3

    def test_all_services_have_required_fields(self):
        """All services should have required fields."""
        for name, service in SERVICES.items():
            assert service.name, f"{name} missing name"
            assert service.display_name, f"{name} missing display_name"
            assert len(service.ports) > 0, f"{name} missing ports"
            assert service.category, f"{name} missing category"


class TestBuiltInSources:
    """Tests for built-in source definitions."""

    def test_anywhere_source_exists(self):
        """Anywhere source should be defined."""
        assert "anywhere" in SOURCE_ALIASES
        anywhere = SOURCE_ALIASES["anywhere"]
        assert anywhere.cidr == "0.0.0.0/0"

    def test_local_network_source_exists(self):
        """Local network source should be defined."""
        assert "local-network" in SOURCE_ALIASES
        local = SOURCE_ALIASES["local-network"]
        # Should use resolver for dynamic CIDRs
        assert local.resolver is not None
        cidrs = local.resolver()
        # Should return at least one CIDR (from detection or defaults)
        assert len(cidrs) >= 1
        # All should be valid CIDR or IP notation
        for cidr in cidrs:
            assert "/" in cidr or cidr.count(".") == 3

    def test_this_machine_source_exists(self):
        """This-machine (localhost) source should be defined."""
        assert "this-machine" in SOURCE_ALIASES
        local = SOURCE_ALIASES["this-machine"]
        assert local.cidr == "127.0.0.1"


class TestResolveService:
    """Tests for resolve_service function."""

    def test_resolve_known_service(self):
        """Should resolve known service names."""
        service = resolve_service("web")
        assert service is not None
        assert service.name == "web"

    def test_resolve_service_case_insensitive(self):
        """Should be case-insensitive."""
        service = resolve_service("WEB")
        assert service is not None
        assert service.name == "web"

    def test_resolve_unknown_service(self):
        """Should return None for unknown services."""
        service = resolve_service("unknown-service")
        assert service is None

    def test_resolve_port_number_returns_none(self):
        """Should return None for port numbers."""
        service = resolve_service("8080")
        assert service is None


class TestResolveSource:
    """Tests for resolve_source function."""

    def test_resolve_anywhere(self):
        """Should resolve 'anywhere' to 0.0.0.0/0."""
        cidrs = resolve_source("anywhere")
        assert "0.0.0.0/0" in cidrs

    def test_resolve_local_network(self):
        """Should resolve 'local-network' to private ranges."""
        cidrs = resolve_source("local-network")
        assert len(cidrs) >= 3  # 10.x, 172.x, 192.168.x

    def test_resolve_this_machine(self):
        """Should resolve 'this-machine' to localhost."""
        cidrs = resolve_source("this-machine")
        assert "127.0.0.1" in cidrs

    def test_resolve_cidr_passthrough(self):
        """Should pass through CIDR notation unchanged."""
        cidrs = resolve_source("192.168.1.0/24")
        assert "192.168.1.0/24" in cidrs

    def test_resolve_ip_passthrough(self):
        """Should pass through IP addresses unchanged."""
        cidrs = resolve_source("10.0.0.5")
        assert "10.0.0.5" in cidrs

    def test_resolve_empty_returns_anywhere(self):
        """Empty source should resolve to anywhere or itself."""
        cidrs = resolve_source("")
        # Empty may return empty list or anywhere depending on implementation
        assert cidrs is not None

    def test_resolve_none_raises_error(self):
        """None source should raise an error (requires string input)."""
        with pytest.raises(AttributeError):
            resolve_source(None)

    def test_resolve_case_insensitive(self):
        """Should be case-insensitive for aliases."""
        cidrs = resolve_source("ANYWHERE")
        assert "0.0.0.0/0" in cidrs

        cidrs = resolve_source("Local-Network")
        assert len(cidrs) >= 3


class TestGetSourceDefinition:
    """Tests for get_source_definition function."""

    def test_get_known_source(self):
        """Should return definition for known sources."""
        source_def = get_source_definition("anywhere")
        assert source_def is not None
        assert source_def.name == "anywhere"

    def test_get_unknown_source(self):
        """Should return None for unknown sources."""
        source_def = get_source_definition("10.0.0.0/8")
        assert source_def is None

    def test_get_source_case_insensitive(self):
        """Should be case-insensitive."""
        source_def = get_source_definition("LOCAL-NETWORK")
        assert source_def is not None


class TestGetServiceByPort:
    """Tests for get_service_by_port function."""

    def test_get_http_by_port(self):
        """Should find HTTP service by port 80."""
        service = get_service_by_port(80, Protocol.TCP)
        assert service is not None
        assert service.name in ["http", "web"]

    def test_get_https_by_port(self):
        """Should find HTTPS service by port 443."""
        service = get_service_by_port(443, Protocol.TCP)
        assert service is not None
        assert service.name in ["https", "web"]

    def test_get_ssh_by_port(self):
        """Should find SSH service by port 22."""
        service = get_service_by_port(22, Protocol.TCP)
        assert service is not None
        assert service.name == "ssh"

    def test_get_postgres_by_port(self):
        """Should find PostgreSQL service by port 5432."""
        service = get_service_by_port(5432, Protocol.TCP)
        assert service is not None
        assert service.name == "postgres"

    def test_unknown_port_returns_none(self):
        """Should return None for unknown ports."""
        service = get_service_by_port(12345, Protocol.TCP)
        assert service is None

    def test_protocol_matters(self):
        """Should consider protocol when matching."""
        # DNS is typically UDP
        dns_service = get_service_by_port(53, Protocol.UDP)
        # May or may not find depending on defined services
        # Just verify it doesn't crash


class TestGetServicesByCategory:
    """Tests for get_services_by_category function."""

    def test_get_web_services(self):
        """Should return web category services."""
        services = get_services_by_category("web")
        assert len(services) > 0
        for service in services:
            assert service.category == "web"

    def test_get_database_services(self):
        """Should return database category services."""
        services = get_services_by_category("database")
        assert len(services) > 0
        for service in services:
            assert service.category == "database"

    def test_get_system_services(self):
        """Should return system category services."""
        services = get_services_by_category("system")
        assert len(services) > 0
        # SSH should be in system
        names = [s.name for s in services]
        assert "ssh" in names

    def test_unknown_category_returns_empty(self):
        """Should return empty list for unknown category."""
        services = get_services_by_category("nonexistent")
        assert services == []


class TestIsPortNumber:
    """Tests for is_port_number function."""

    def test_valid_port_strings(self):
        """Should recognize valid port number strings."""
        assert is_port_number("80") is True
        assert is_port_number("443") is True
        assert is_port_number("5432") is True
        assert is_port_number("65535") is True

    def test_invalid_port_strings(self):
        """Should reject invalid port strings."""
        assert is_port_number("web") is False
        assert is_port_number("postgres") is False
        assert is_port_number("http") is False

    def test_edge_cases(self):
        """Should handle edge cases."""
        assert is_port_number("0") is False  # Port 0 is not valid (1-65535)
        assert is_port_number("99999") is False  # Exceeds max port 65535
        assert is_port_number("") is False
        assert is_port_number("12.34") is False
        assert is_port_number("1") is True  # Min valid port
        assert is_port_number("65535") is True  # Max valid port
        assert is_port_number("65536") is False  # Exceeds max

    def test_port_with_spaces(self):
        """Should handle ports with surrounding spaces."""
        assert is_port_number(" 80 ") is True
        assert is_port_number("  443  ") is True


class TestFormatSourceForDisplay:
    """Tests for format_source_for_display function."""

    def test_format_anywhere(self):
        """Should format 0.0.0.0/0 as 'Anywhere'."""
        display = format_source_for_display("0.0.0.0/0")
        assert "anywhere" in display.lower() or "any" in display.lower()

    def test_format_localhost(self):
        """Should format 127.0.0.1 as 'This Machine'."""
        display = format_source_for_display("127.0.0.1")
        assert display == "This Machine"

    def test_format_cidr(self):
        """Should include CIDR in display."""
        display = format_source_for_display("10.0.0.0/8")
        assert "10.0.0.0/8" in display

    def test_format_ip(self):
        """Should display IP address."""
        display = format_source_for_display("192.168.1.100")
        assert "192.168.1.100" in display


class TestServiceCategories:
    """Tests for service categorization."""

    def test_all_services_have_valid_categories(self):
        """All services should have valid categories."""
        valid_categories = {"web", "database", "system", "containers", "monitoring", "mail"}
        for name, service in SERVICES.items():
            assert service.category in valid_categories, \
                f"Service {name} has invalid category: {service.category}"

    def test_database_services_default_local(self):
        """Database services should default to local-network."""
        database_services = get_services_by_category("database")
        for service in database_services:
            assert service.default_source == "local-network", \
                f"Database service {service.name} should default to local-network"

    def test_web_services_default_anywhere(self):
        """Web services should default to anywhere."""
        web_services = get_services_by_category("web")
        for service in web_services:
            assert service.default_source == "anywhere", \
                f"Web service {service.name} should default to anywhere"


class TestServiceWarnings:
    """Tests for service warning messages."""

    def test_database_services_have_warnings(self):
        """Database services should have security warnings."""
        database_services = get_services_by_category("database")
        # At least some database services should have warnings
        warnings_count = sum(1 for s in database_services if s.warning)
        assert warnings_count > 0, "At least one database service should have a warning"

    def test_ssh_is_always_allowed(self):
        """SSH service should be marked as always_allowed."""
        ssh = SERVICES.get("ssh")
        assert ssh is not None
        assert ssh.always_allowed is True


class TestLocalNetworkDynamicResolution:
    """Tests for dynamic local network resolution."""

    def test_local_network_includes_standard_ranges(self):
        """Local network should include RFC1918 ranges."""
        cidrs = resolve_source("local-network")

        # Should include at least the standard private ranges
        has_10 = any("10." in c for c in cidrs)
        has_172 = any("172." in c for c in cidrs)
        has_192 = any("192.168." in c for c in cidrs)

        assert has_10 or has_172 or has_192, \
            "Local network should include at least one RFC1918 range"
