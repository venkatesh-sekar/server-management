"""Auto-installation of optional Python dependencies.

Handles the complexity of installing packages in various environments:
- Docker containers with externally-managed Python (PEP 668)
- Alpine Linux with apk
- Debian/Ubuntu with apt
- Standard venv/virtualenv environments
"""

import importlib
import os
import shutil
import subprocess
import sys

from sm.core.exceptions import PrerequisiteError
from sm.core.output import console


def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def _detect_package_manager() -> str | None:
    """Detect available system package manager.

    Returns:
        'apt', 'apk', or None
    """
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("apk"):
        return "apk"
    return None


def _is_externally_managed() -> bool:
    """Check if Python environment is externally managed (PEP 668)."""
    # Check for EXTERNALLY-MANAGED marker file
    markers = [
        # Standard location
        os.path.join(sys.prefix, "EXTERNALLY-MANAGED"),
        # Debian/Ubuntu location
        f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/EXTERNALLY-MANAGED",
    ]
    return any(os.path.exists(m) for m in markers)


def _is_venv() -> bool:
    """Check if running in a virtual environment."""
    return sys.prefix != sys.base_prefix


def _run_install(cmd: list[str], pkg_name: str) -> bool:
    """Run an installation command.

    Args:
        cmd: Command and arguments
        pkg_name: Package name for logging

    Returns:
        True if successful, False otherwise
    """
    try:
        console.step(f"Installing {pkg_name}...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        if result.returncode == 0:
            console.success(f"Successfully installed {pkg_name}")
            return True
        console.verbose(f"Installation failed: {result.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        console.warn("Installation timed out")
        return False
    except Exception as e:
        console.verbose(f"Installation error: {e}")
        return False


def ensure_package(
    pip_name: str,
    apt_name: str | None = None,
    apk_name: str | None = None,
) -> bool:
    """Ensure a Python package is installed, prompting to install if missing.

    Tries installation methods in this order:
    1. Check if already installed
    2. Prompt user for confirmation
    3. apt (Debian/Ubuntu) if available and root
    4. apk (Alpine) if available and root
    5. pip with --break-system-packages (for externally-managed envs)
    6. pip (for venvs or older systems)

    Args:
        pip_name: Package name for pip (e.g., "boto3")
        apt_name: Package name for apt (e.g., "python3-boto3")
        apk_name: Package name for apk (e.g., "py3-boto3")

    Returns:
        True if package is available

    Raises:
        PrerequisiteError: If user declines or installation fails
    """
    # 1. Check if already installed
    try:
        importlib.import_module(pip_name)
        return True
    except ImportError:
        pass

    # Package not installed - prepare to install
    console.warn(f"{pip_name} is required but not installed.")

    pkg_manager = _detect_package_manager()
    is_root = _is_root()
    externally_managed = _is_externally_managed()
    in_venv = _is_venv()

    # Determine which method we'll try first
    if pkg_manager == "apt" and apt_name and is_root:
        method_desc = f"apt install {apt_name}"
    elif pkg_manager == "apk" and apk_name and is_root:
        method_desc = f"apk add {apk_name}"
    elif in_venv:
        method_desc = f"pip install {pip_name}"
    elif externally_managed:
        method_desc = f"pip install --break-system-packages {pip_name}"
    else:
        method_desc = f"pip install {pip_name}"

    # 2. Prompt user for confirmation
    try:
        response = input(f"\nInstall {pip_name} via {method_desc}? [Y/n]: ").strip().lower()
        if response in ("n", "no"):
            hint = _get_manual_install_hint(pip_name, apt_name, apk_name, pkg_manager)
            raise PrerequisiteError(
                f"{pip_name} is required for this operation",
                hint=hint,
            )
    except EOFError:
        # Non-interactive mode - proceed with installation
        console.verbose("Non-interactive mode, proceeding with installation")

    # 3. Try apt (Debian/Ubuntu)
    if pkg_manager == "apt" and apt_name and is_root:
        # Update package list first (quietly)
        subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True,
            timeout=120,
        )
        if _run_install(["apt-get", "install", "-y", "-qq", apt_name], apt_name):
            # Verify import works after installation
            try:
                importlib.import_module(pip_name)
                return True
            except ImportError:
                console.verbose("Package installed but import still fails")

    # 4. Try apk (Alpine)
    if pkg_manager == "apk" and apk_name and is_root:
        if _run_install(["apk", "add", "--no-cache", apk_name], apk_name):
            try:
                importlib.import_module(pip_name)
                return True
            except ImportError:
                console.verbose("Package installed but import still fails")

    # 5. Try pip with --break-system-packages (for externally-managed envs)
    if externally_managed and not in_venv:
        if _run_install(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", pip_name],
            pip_name,
        ):
            try:
                importlib.import_module(pip_name)
                return True
            except ImportError:
                console.verbose("Package installed but import still fails")

    # 6. Try regular pip (for venvs or older systems)
    if _run_install([sys.executable, "-m", "pip", "install", pip_name], pip_name):
        try:
            importlib.import_module(pip_name)
            return True
        except ImportError:
            console.verbose("Package installed but import still fails")

    # All methods failed
    hint = _get_manual_install_hint(pip_name, apt_name, apk_name, pkg_manager)
    raise PrerequisiteError(
        f"Failed to install {pip_name}",
        hint=hint,
    )


def _get_manual_install_hint(
    pip_name: str,
    apt_name: str | None,
    apk_name: str | None,
    pkg_manager: str | None,
) -> str:
    """Generate a helpful hint for manual installation."""
    hints = []

    if pkg_manager == "apt" and apt_name:
        hints.append(f"sudo apt install {apt_name}")
    elif pkg_manager == "apk" and apk_name:
        hints.append(f"sudo apk add {apk_name}")

    hints.append(f"pip install {pip_name}")

    return "Install manually with: " + " or ".join(hints)
