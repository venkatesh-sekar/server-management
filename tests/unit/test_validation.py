"""Unit tests for the validation module."""

import pytest

from sm.core.validation import (
    validate_identifier,
    validate_cidr,
    validate_port,
    validate_url,
    validate_path,
    validate_password,
    generate_password,
    MAX_IDENTIFIER_LENGTH,
    PG_RESERVED_WORDS,
    Validator,
)
from sm.core.exceptions import ValidationError


class TestValidateIdentifier:
    """Tests for PostgreSQL identifier validation."""

    def test_valid_identifier(self):
        """Valid identifiers should pass."""
        assert validate_identifier("mydb") == "mydb"
        assert validate_identifier("my_database") == "my_database"
        assert validate_identifier("DB1") == "DB1"
        assert validate_identifier("_private") == "_private"
        assert validate_identifier("CamelCase") == "CamelCase"

    def test_empty_identifier(self):
        """Empty identifiers should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_identifier("")
        assert "cannot be empty" in str(exc.value)

    def test_too_long_identifier(self):
        """Identifiers exceeding 63 chars should fail."""
        long_name = "a" * (MAX_IDENTIFIER_LENGTH + 1)
        with pytest.raises(ValidationError) as exc:
            validate_identifier(long_name)
        assert "exceeds maximum length" in str(exc.value)

    def test_max_length_identifier(self):
        """Identifiers at exactly 63 chars should pass."""
        valid_name = "a" * MAX_IDENTIFIER_LENGTH
        assert validate_identifier(valid_name) == valid_name

    def test_invalid_start_with_number(self):
        """Identifiers starting with number should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_identifier("1database")
        assert "Invalid" in str(exc.value)

    def test_invalid_special_characters(self):
        """Identifiers with special chars should fail."""
        invalid_names = ["my-db", "my.db", "my db", "my$db", "my@db"]
        for name in invalid_names:
            with pytest.raises(ValidationError):
                validate_identifier(name)

    def test_reserved_words(self):
        """PostgreSQL reserved words should fail."""
        for word in ["select", "user", "table", "create", "database"]:
            with pytest.raises(ValidationError) as exc:
                validate_identifier(word)
            assert "reserved word" in str(exc.value).lower()

    def test_reserved_words_case_insensitive(self):
        """Reserved word check should be case-insensitive."""
        with pytest.raises(ValidationError):
            validate_identifier("SELECT")
        with pytest.raises(ValidationError):
            validate_identifier("Select")

    def test_confusing_names_with_warning(self):
        """Confusing names should pass with allow_warnings=True."""
        # Should pass with default settings
        assert validate_identifier("admin", allow_warnings=True) == "admin"

    def test_confusing_names_without_warning(self):
        """Confusing names should fail with allow_warnings=False."""
        with pytest.raises(ValidationError) as exc:
            validate_identifier("admin", allow_warnings=False)
        assert "confusing" in str(exc.value).lower()


class TestValidateCIDR:
    """Tests for CIDR notation validation."""

    def test_valid_cidr(self):
        """Valid CIDR notations should pass."""
        assert validate_cidr("10.0.0.0/24") == "10.0.0.0/24"
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_cidr("172.16.0.0/12") == "172.16.0.0/12"

    def test_invalid_cidr(self):
        """Invalid CIDR notations should fail."""
        with pytest.raises(ValidationError):
            validate_cidr("invalid")
        with pytest.raises(ValidationError):
            validate_cidr("256.0.0.0/8")
        with pytest.raises(ValidationError):
            validate_cidr("10.0.0.0/33")

    def test_dangerous_wildcard(self):
        """0.0.0.0/0 should fail by default."""
        with pytest.raises(ValidationError) as exc:
            validate_cidr("0.0.0.0/0")
        assert "ANYWHERE" in str(exc.value)

    def test_wildcard_allowed(self):
        """0.0.0.0/0 should pass with warn_broad=False."""
        assert validate_cidr("0.0.0.0/0", warn_broad=False) == "0.0.0.0/0"

    def test_broad_range_warning(self):
        """Very broad ranges should fail by default."""
        with pytest.raises(ValidationError) as exc:
            validate_cidr("10.0.0.0/8")
        assert "broad range" in str(exc.value).lower()


class TestValidatePort:
    """Tests for port number validation."""

    def test_valid_ports(self):
        """Valid port numbers should pass."""
        assert validate_port(80) == 80
        assert validate_port(443) == 443
        assert validate_port(5432) == 5432
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_invalid_ports(self):
        """Invalid port numbers should fail."""
        with pytest.raises(ValidationError):
            validate_port(0)
        with pytest.raises(ValidationError):
            validate_port(65536)
        with pytest.raises(ValidationError):
            validate_port(-1)


class TestValidateURL:
    """Tests for URL validation."""

    def test_valid_urls(self):
        """Valid URLs should pass."""
        assert validate_url("http://example.com") == "http://example.com"
        assert validate_url("https://example.com") == "https://example.com"
        assert validate_url("http://localhost:8080") == "http://localhost:8080"

    def test_url_without_scheme(self):
        """URLs without scheme should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_url("example.com")
        assert "scheme" in str(exc.value).lower()

    def test_url_without_host(self):
        """URLs without host should fail."""
        with pytest.raises(ValidationError):
            validate_url("http://")

    def test_require_https(self):
        """HTTP should fail when HTTPS required."""
        with pytest.raises(ValidationError) as exc:
            validate_url("http://example.com", require_https=True)
        assert "HTTPS is required" in str(exc.value)

    def test_disallowed_scheme(self):
        """Unsupported schemes should fail."""
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com")


class TestValidatePath:
    """Tests for path validation."""

    def test_valid_absolute_path(self):
        """Valid absolute paths should pass."""
        assert validate_path("/var/log/app.log") == "/var/log/app.log"
        assert validate_path("/etc/config.yaml") == "/etc/config.yaml"

    def test_relative_path_fails(self):
        """Relative paths should fail by default."""
        with pytest.raises(ValidationError):
            validate_path("relative/path")

    def test_path_traversal(self):
        """Path traversal attempts should fail."""
        with pytest.raises(ValidationError):
            validate_path("/var/log/../etc/passwd")
        with pytest.raises(ValidationError):
            validate_path("/var/log/..%2f..%2fetc/passwd")

    def test_command_injection(self):
        """Command injection patterns should fail."""
        dangerous_paths = [
            "/var/log/$(whoami)",
            "/var/log/`id`",
            "/var/log/test|cat /etc/passwd",
            "/var/log/test;rm -rf /",
        ]
        for path in dangerous_paths:
            with pytest.raises(ValidationError):
                validate_path(path)

    def test_must_start_with(self):
        """Path prefix requirement should be enforced."""
        assert validate_path("/var/log/app.log", must_start_with="/var/log") == "/var/log/app.log"
        with pytest.raises(ValidationError):
            validate_path("/etc/passwd", must_start_with="/var/log")


class TestValidatePassword:
    """Tests for password validation."""

    def test_valid_password(self):
        """Valid passwords should pass."""
        valid = "SecureP@ssw0rd123!"
        assert validate_password(valid) == valid

    def test_too_short(self):
        """Short passwords should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_password("Short1!")
        # Details contain the specific issue
        assert any("at least" in d.lower() for d in exc.value.details)

    def test_missing_uppercase(self):
        """Passwords without uppercase should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_password("nouppercase123456!")
        assert any("uppercase" in d.lower() for d in exc.value.details)

    def test_missing_lowercase(self):
        """Passwords without lowercase should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_password("NOLOWERCASE123456!")
        assert any("lowercase" in d.lower() for d in exc.value.details)

    def test_missing_digit(self):
        """Passwords without digits should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_password("NoDigitsHere!!!!")
        assert any("digit" in d.lower() for d in exc.value.details)

    def test_missing_special(self):
        """Passwords without special chars should fail."""
        with pytest.raises(ValidationError) as exc:
            validate_password("NoSpecialChars123")
        assert any("special" in d.lower() for d in exc.value.details)


class TestGeneratePassword:
    """Tests for password generation."""

    def test_default_length(self):
        """Default length should be 32."""
        password = generate_password()
        assert len(password) == 32

    def test_custom_length(self):
        """Custom length should be respected."""
        password = generate_password(length=24)
        assert len(password) == 24

    def test_minimum_length(self):
        """Length below 16 should fail."""
        with pytest.raises(ValidationError):
            generate_password(length=15)

    def test_password_contains_all_types(self):
        """Generated password should contain all character types."""
        password = generate_password()
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in "!@#$%^&*()-_=+" for c in password)

    def test_password_uniqueness(self):
        """Generated passwords should be unique."""
        passwords = [generate_password() for _ in range(10)]
        assert len(set(passwords)) == 10


class TestFluentValidator:
    """Tests for the fluent Validator class."""

    def test_basic_chain(self):
        """Basic validation chain should work."""
        result = Validator("mydb").identifier("database").get()
        assert result == "mydb"

    def test_required(self):
        """Required validation should work."""
        with pytest.raises(ValidationError):
            Validator("").required("Value is required").get()

        with pytest.raises(ValidationError):
            Validator(None).required().get()

    def test_get_required(self):
        """get_required should fail on None."""
        with pytest.raises(ValidationError):
            Validator(None).get_required()

    def test_max_length(self):
        """max_length validation should work."""
        assert Validator("short").max_length(10).get() == "short"
        with pytest.raises(ValidationError):
            Validator("toolongvalue").max_length(5).get()

    def test_matches(self):
        """Regex pattern matching should work."""
        assert Validator("abc123").matches(r"^[a-z0-9]+$", "Invalid").get() == "abc123"
        with pytest.raises(ValidationError):
            Validator("ABC!@#").matches(r"^[a-z0-9]+$", "Invalid").get()
