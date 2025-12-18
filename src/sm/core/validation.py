"""Input validation utilities.

Provides comprehensive validation for:
- PostgreSQL identifiers (database names, usernames)
- Network configurations (CIDR, URLs, ports)
- Paths (with traversal prevention)
- Passwords (strength requirements)

All validators return the validated value or raise ValidationError.
"""

import ipaddress
import re
import secrets
import string
from typing import Optional
from urllib.parse import urlparse

from sm.core.exceptions import ValidationError


# PostgreSQL reserved words (comprehensive list from PG 16 docs)
PG_RESERVED_WORDS: frozenset[str] = frozenset({
    # SQL Reserved Words
    "all", "analyse", "analyze", "and", "any", "array", "as", "asc",
    "asymmetric", "authorization", "between", "bigint", "binary", "bit",
    "boolean", "both", "case", "cast", "char", "character", "check",
    "coalesce", "collate", "collation", "column", "concurrently",
    "constraint", "create", "cross", "current_catalog", "current_date",
    "current_role", "current_schema", "current_time", "current_timestamp",
    "current_user", "dec", "decimal", "default", "deferrable", "desc",
    "distinct", "do", "else", "end", "except", "exists", "extract",
    "false", "fetch", "float", "for", "foreign", "freeze", "from",
    "full", "grant", "greatest", "group", "grouping", "having", "ilike",
    "in", "initially", "inner", "inout", "int", "integer", "intersect",
    "interval", "into", "is", "isnull", "join", "json", "json_array",
    "json_arrayagg", "json_object", "json_objectagg", "json_scalar",
    "lateral", "leading", "least", "left", "like", "limit", "localtime",
    "localtimestamp", "national", "natural", "nchar", "none", "normalize",
    "not", "notnull", "null", "nullif", "numeric", "offset", "on", "only",
    "or", "order", "out", "outer", "overlaps", "overlay", "placing",
    "position", "precision", "primary", "real", "references", "returning",
    "right", "row", "select", "session_user", "setof", "similar",
    "smallint", "some", "substring", "symmetric", "system_user", "table",
    "tablesample", "then", "time", "timestamp", "to", "trailing", "treat",
    "trim", "true", "union", "unique", "user", "using", "values",
    "varchar", "variadic", "verbose", "when", "where", "window", "with",
    "xmlattributes", "xmlconcat", "xmlelement", "xmlexists", "xmlforest",
    "xmlnamespaces", "xmlparse", "xmlpi", "xmlroot", "xmlserialize", "xmltable",
    # Non-reserved but problematic
    "database", "index", "password", "role", "schema", "sequence",
    "trigger", "type", "view", "owner", "public", "template",
})

# Words that warrant warnings
CONFUSING_WORDS: frozenset[str] = frozenset({
    "admin", "administrator", "backup", "config", "data", "default",
    "guest", "master", "public", "root", "superuser", "sys", "system",
    "temp", "test", "tmp", "undefined", "unknown", "postgres", "pgbouncer",
})

# PostgreSQL identifier pattern
IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Maximum identifier length
MAX_IDENTIFIER_LENGTH = 63


def validate_identifier(
    value: str,
    identifier_type: str = "identifier",
    allow_warnings: bool = True,
) -> str:
    """Validate a PostgreSQL identifier (database name, username, etc.).

    Rules:
    - Must start with letter or underscore
    - Can contain letters, digits, underscores
    - Cannot be a reserved word
    - Max 63 characters

    Args:
        value: The identifier to validate
        identifier_type: Type for error messages (e.g., "database", "user")
        allow_warnings: If False, confusing names also raise errors

    Returns:
        The validated identifier

    Raises:
        ValidationError: If validation fails
    """
    if not value:
        raise ValidationError(
            f"{identifier_type.title()} name cannot be empty",
            hint="Provide a valid name",
        )

    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValidationError(
            f"{identifier_type.title()} name exceeds maximum length "
            f"({len(value)} > {MAX_IDENTIFIER_LENGTH})",
            hint=f"Use a name with {MAX_IDENTIFIER_LENGTH} or fewer characters",
            details=[f"Provided: {value[:50]}..."],
        )

    if not IDENTIFIER_PATTERN.match(value):
        raise ValidationError(
            f"Invalid {identifier_type} name: '{value}'",
            hint="Must start with a letter or underscore, contain only letters, digits, and underscores",
            details=[_suggest_valid_name(value)],
        )

    lower_value = value.lower()

    if lower_value in PG_RESERVED_WORDS:
        raise ValidationError(
            f"'{value}' is a PostgreSQL reserved word",
            hint=f"Try '{value}_db' or '{value}_user' instead",
        )

    if not allow_warnings and lower_value in CONFUSING_WORDS:
        raise ValidationError(
            f"'{value}' may be confusing as a {identifier_type} name",
            hint="Choose a more descriptive name",
        )

    return value


def _suggest_valid_name(identifier: str) -> str:
    """Generate a suggestion for a valid identifier from an invalid one."""
    # Remove invalid characters
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", identifier)

    # Ensure starts with letter or underscore
    if cleaned and cleaned[0].isdigit():
        cleaned = f"_{cleaned}"

    # Handle empty result
    if not cleaned:
        cleaned = "unnamed"

    # Truncate if needed
    suggestion = cleaned[:MAX_IDENTIFIER_LENGTH]
    return f"Suggestion: {suggestion}"


def validate_cidr(value: str, warn_broad: bool = True) -> str:
    """Validate CIDR notation for network ranges.

    Args:
        value: CIDR string to validate (e.g., "10.0.0.0/24")
        warn_broad: If True, raises error for 0.0.0.0/0

    Returns:
        The validated CIDR string

    Raises:
        ValidationError: If validation fails
    """
    value = value.strip()

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValidationError(
            f"Invalid CIDR notation: {value}",
            hint="Use format like 10.0.0.0/24 or 192.168.1.0/24",
            details=[str(e)],
        ) from e

    # Check for dangerous wildcards
    if warn_broad and value in ("0.0.0.0/0", "::/0"):
        raise ValidationError(
            f"'{value}' allows access from ANYWHERE on the internet",
            hint="Use a more restrictive CIDR range for security",
            details=[
                "This is extremely dangerous for production systems",
                "Consider using your VPC CIDR or specific IP ranges",
            ],
        )

    # Warn about very broad ranges
    if warn_broad and network.prefixlen <= 8:
        host_count = network.num_addresses
        raise ValidationError(
            f"'{value}' is an extremely broad range ({host_count:,} addresses)",
            hint="Use a more restrictive CIDR (e.g., /16 or smaller)",
        )

    return value


def validate_port(value: int) -> int:
    """Validate a port number.

    Args:
        value: Port number to validate

    Returns:
        The validated port number

    Raises:
        ValidationError: If port is out of valid range
    """
    if not 1 <= value <= 65535:
        raise ValidationError(
            f"Invalid port number: {value}",
            hint="Port must be between 1 and 65535",
        )

    if value < 1024:
        # Not an error, just informational
        pass  # Privileged ports are OK for system services

    return value


def validate_url(
    value: str,
    require_https: bool = False,
    allowed_schemes: Optional[frozenset[str]] = None,
) -> str:
    """Validate a URL.

    Args:
        value: URL to validate
        require_https: If True, only HTTPS URLs are allowed
        allowed_schemes: Set of allowed schemes (default: http, https)

    Returns:
        The validated URL

    Raises:
        ValidationError: If validation fails
    """
    value = value.strip()

    if not allowed_schemes:
        allowed_schemes = frozenset({"http", "https"})

    try:
        parsed = urlparse(value)
    except Exception as e:
        raise ValidationError(
            f"Invalid URL format: {value}",
            hint="Provide a valid URL",
            details=[str(e)],
        ) from e

    if not parsed.scheme:
        raise ValidationError(
            f"URL must include a scheme: {value}",
            hint=f"Use https://{value}",
        )

    if parsed.scheme.lower() not in allowed_schemes:
        raise ValidationError(
            f"URL scheme '{parsed.scheme}' not allowed",
            hint=f"Use one of: {', '.join(sorted(allowed_schemes))}",
        )

    if require_https and parsed.scheme.lower() != "https":
        raise ValidationError(
            "HTTPS is required for security",
            hint=f"Change {parsed.scheme}:// to https://",
        )

    if not parsed.netloc:
        raise ValidationError(
            f"URL must include a host: {value}",
            hint="Provide a complete URL like https://example.com:8080",
        )

    return value


def validate_path(
    value: str,
    must_be_absolute: bool = True,
    must_start_with: Optional[str] = None,
) -> str:
    """Validate a file path with traversal prevention.

    Args:
        value: Path to validate
        must_be_absolute: Require absolute path
        must_start_with: Required path prefix

    Returns:
        The validated path

    Raises:
        ValidationError: If validation fails
    """
    # Check for dangerous patterns
    dangerous_patterns = [
        "..",           # Parent directory traversal
        "$",            # Variable expansion
        "`",            # Command substitution
        "|",            # Pipe
        ";",            # Command separator
        "&",            # Background/AND
        "\n",           # Newline injection
        "\r",           # Carriage return
        "\x00",         # Null byte
    ]

    for pattern in dangerous_patterns:
        if pattern in value:
            raise ValidationError(
                f"Path contains dangerous pattern: {repr(pattern)}",
                hint="Use a simple path without special characters",
            )

    if must_be_absolute and not value.startswith("/"):
        raise ValidationError(
            f"Path must be absolute: {value}",
            hint=f"Use /{value}",
        )

    if must_start_with and not value.startswith(must_start_with):
        raise ValidationError(
            f"Path must start with '{must_start_with}'",
            hint=f"Allowed paths start with: {must_start_with}",
        )

    return value


# Password validation
# Use only alphanumeric characters to avoid encoding issues with special chars
# Increased default length to 48 to compensate for reduced character set
# 48 chars from 62-char alphabet = ~286 bits of entropy (very secure)
DEFAULT_PASSWORD_LENGTH = 48
PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """Generate a cryptographically secure password.

    Uses only alphanumeric characters (a-z, A-Z, 0-9) to avoid encoding
    issues with special characters in connection strings, URLs, and configs.

    Args:
        length: Password length (minimum 16, default 48)

    Returns:
        Generated password

    Raises:
        ValidationError: If length is too short
    """
    if length < 16:
        raise ValidationError(
            "Password length must be at least 16 characters",
            hint="Use a longer password for security",
        )

    # Ensure at least one of each character type for compatibility
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]

    # Fill remaining with random alphanumeric characters
    remaining = length - len(password_chars)
    password_chars.extend(
        secrets.choice(PASSWORD_ALPHABET) for _ in range(remaining)
    )

    # Cryptographic shuffle using Fisher-Yates
    result = password_chars.copy()
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]

    return "".join(result)


def validate_password(
    password: str,
    min_length: int = 16,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digit: bool = True,
    require_special: bool = False,
) -> str:
    """Validate password strength.

    Args:
        password: Password to validate
        min_length: Minimum required length
        require_uppercase: Require at least one uppercase letter
        require_lowercase: Require at least one lowercase letter
        require_digit: Require at least one digit
        require_special: Require at least one special character (default False
            to avoid encoding issues with special chars)

    Returns:
        The validated password

    Raises:
        ValidationError: If password doesn't meet requirements
    """
    issues = []

    if len(password) < min_length:
        issues.append(f"Must be at least {min_length} characters (got {len(password)})")

    if require_uppercase and not any(c.isupper() for c in password):
        issues.append("Must contain at least one uppercase letter")

    if require_lowercase and not any(c.islower() for c in password):
        issues.append("Must contain at least one lowercase letter")

    if require_digit and not any(c.isdigit() for c in password):
        issues.append("Must contain at least one digit")

    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if require_special and not any(c in special_chars for c in password):
        issues.append(f"Must contain at least one special character ({special_chars})")

    # Check for common weak patterns
    weak_patterns = [
        (r"^(.)\1+$", "All same character"),
        (r"^[a-z]+$", "All lowercase letters"),
        (r"^[A-Z]+$", "All uppercase letters"),
        (r"^[0-9]+$", "All digits"),
        (r"^(123|abc|qwe)", "Sequential pattern"),
    ]

    for pattern, description in weak_patterns:
        if re.match(pattern, password, re.IGNORECASE):
            issues.append(f"Weak pattern detected: {description}")
            break

    if issues:
        raise ValidationError(
            "Password does not meet security requirements",
            details=issues,
            hint="Use a generated password or ensure it meets all requirements",
        )

    return password


class Validator:
    """Fluent validator for building validation chains.

    Example:
        validated = (
            Validator(user_input)
            .required("Database name is required")
            .identifier("database")
            .get()
        )
    """

    def __init__(self, value: Optional[str]) -> None:
        self._value = value

    def required(self, message: str = "Value is required") -> "Validator":
        """Ensure value is not None or empty."""
        if not self._value:
            raise ValidationError(message)
        return self

    def identifier(self, identifier_type: str = "identifier") -> "Validator":
        """Validate as PostgreSQL identifier."""
        if self._value:
            self._value = validate_identifier(self._value, identifier_type)
        return self

    def cidr(self) -> "Validator":
        """Validate as CIDR notation."""
        if self._value:
            self._value = validate_cidr(self._value)
        return self

    def url(self, require_https: bool = False) -> "Validator":
        """Validate as URL."""
        if self._value:
            self._value = validate_url(self._value, require_https=require_https)
        return self

    def path(self, must_start_with: Optional[str] = None) -> "Validator":
        """Validate as file path."""
        if self._value:
            self._value = validate_path(self._value, must_start_with=must_start_with)
        return self

    def max_length(self, length: int, name: str = "Value") -> "Validator":
        """Ensure value doesn't exceed maximum length."""
        if self._value and len(self._value) > length:
            raise ValidationError(f"{name} exceeds maximum length of {length}")
        return self

    def matches(self, pattern: str, message: str) -> "Validator":
        """Ensure value matches regex pattern."""
        if self._value and not re.match(pattern, self._value):
            raise ValidationError(message)
        return self

    def get(self) -> Optional[str]:
        """Get the validated value."""
        return self._value

    def get_required(self) -> str:
        """Get the validated value, asserting it's not None."""
        if self._value is None:
            raise ValidationError("Value is required")
        return self._value


# B2 bucket name validation
B2_BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")


def validate_b2_bucket_name(name: str) -> str:
    """Validate Backblaze B2 bucket name format.

    B2 bucket naming rules:
    - 6-50 characters
    - Only lowercase letters, numbers, hyphens
    - Must start and end with letter or number
    - Cannot contain consecutive hyphens

    Args:
        name: Bucket name to validate

    Returns:
        The validated bucket name

    Raises:
        ValidationError: If validation fails
    """
    name = name.strip().lower()

    if not name:
        raise ValidationError(
            "Bucket name is required",
            hint="Provide a bucket name like 'mycompany-pg-backups'",
        )

    if len(name) < 6:
        raise ValidationError(
            f"Bucket name must be at least 6 characters (got {len(name)})",
            hint="Use a longer bucket name like 'mycompany-pg-backups'",
        )

    if len(name) > 50:
        raise ValidationError(
            f"Bucket name must be at most 50 characters (got {len(name)})",
            hint="Use a shorter bucket name",
        )

    # For single-character names (shouldn't happen due to length check, but be safe)
    if len(name) == 1:
        if not name.isalnum():
            raise ValidationError(
                "Bucket name must contain only lowercase letters, numbers, and hyphens",
                hint="Use a name like 'mycompany-pg-backups'",
            )
    elif not B2_BUCKET_NAME_PATTERN.match(name):
        raise ValidationError(
            "Bucket name must start and end with a letter or number, "
            "and contain only lowercase letters, numbers, and hyphens",
            hint="Use a name like 'mycompany-pg-backups'",
        )

    if "--" in name:
        raise ValidationError(
            "Bucket name cannot contain consecutive hyphens",
            hint="Use single hyphens between words",
        )

    return name


def validate_backup_passphrase(
    passphrase: str,
    min_length: int = 20,
) -> str:
    """Validate backup encryption passphrase strength.

    Requirements:
    - Minimum 20 characters by default
    - Not entirely whitespace

    Note: Unlike passwords, passphrases can be simpler (just long)
    because they're typically not brute-forced online.

    Args:
        passphrase: Passphrase to validate
        min_length: Minimum required length (default 20)

    Returns:
        The validated passphrase

    Raises:
        ValidationError: If validation fails
    """
    if not passphrase:
        raise ValidationError(
            "Backup passphrase is required",
            hint="Provide a passphrase of at least 20 characters",
        )

    if passphrase != passphrase.strip():
        raise ValidationError(
            "Passphrase should not have leading or trailing whitespace",
            hint="Remove extra spaces from the beginning and end",
        )

    if len(passphrase) < min_length:
        raise ValidationError(
            f"Passphrase must be at least {min_length} characters (got {len(passphrase)})",
            hint="Use a longer passphrase for security",
            details=[
                "A passphrase can be a sentence or phrase that's easy to remember",
                "Example: 'correct horse battery staple' (but use your own!)",
            ],
        )

    # Check for trivially weak passphrases
    if passphrase == passphrase[0] * len(passphrase):
        raise ValidationError(
            "Passphrase cannot be all the same character",
            hint="Use a more complex passphrase",
        )

    return passphrase
