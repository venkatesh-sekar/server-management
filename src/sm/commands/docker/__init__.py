"""Docker management commands.

This module provides Docker-related utilities and fixes.
"""

from typing import Annotated

import typer

# Create docker command group
app = typer.Typer(
    name="docker",
    help="Docker management and fixes.",
    no_args_is_help=True,
)


@app.command("fix-mtu")
def fix_mtu_cmd(
    mtu: Annotated[
        int,
        typer.Option(
            "--mtu",
            help="MTU value to set (default: 1450 for Hetzner Cloud)",
        ),
    ] = 1450,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Preview changes without executing. Shows what would happen.",
            is_flag=True,
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Allow dangerous operations. Required for destructive actions.",
            is_flag=True,
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Skip confirmation prompts. Still requires --force for dangerous ops.",
            is_flag=True,
        ),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase output verbosity. Can be repeated (-v, -vv, -vvv).",
        ),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output.",
            is_flag=True,
        ),
    ] = False,
) -> None:
    """Fix Docker MTU for Hetzner Cloud VXLAN networks.

    Configures Docker daemon to use MTU 1450 for overlay networks,
    preventing packet drops and connectivity issues on Hetzner Cloud.

    [bold]What this does:[/bold]
    - Creates/updates /etc/docker/daemon.json with MTU configuration
    - Restarts Docker daemon to apply changes
    - Preserves existing Docker configuration

    [bold]When to use:[/bold]
    - Hetzner Cloud servers with private networking
    - S3/external connectivity failures
    - Silent packet drops on overlay networks

    [bold]Prerequisites:[/bold]
    - Debian or Ubuntu system
    - Root access
    - Docker installed

    [bold]Examples:[/bold]

        # Apply MTU 1450 fix (Hetzner Cloud default)
        sudo sm docker fix-mtu

        # Preview what would happen
        sm docker fix-mtu --dry-run

        # Use custom MTU value
        sudo sm docker fix-mtu --mtu=1400
    """
    import os
    from sm.commands.docker.fix_mtu import run_fix_mtu
    from sm.core.context import create_context
    from sm.core.exceptions import SMError

    # Create execution context
    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )

    # Check root
    if os.geteuid() != 0:
        ctx.console.error("This operation requires root privileges")
        ctx.console.hint("Run with: sudo sm docker fix-mtu")
        raise typer.Exit(6)

    # Show configuration
    ctx.console.print()
    ctx.console.print("[bold]Docker MTU Fix Configuration[/bold]")
    ctx.console.print(f"  MTU value:      {mtu}")
    ctx.console.print(f"  Config file:    /etc/docker/daemon.json")
    ctx.console.print()

    if not yes and not dry_run:
        if not ctx.console.confirm("Proceed with Docker MTU fix?"):
            ctx.console.warn("Operation cancelled")
            raise typer.Exit(0)

    try:
        run_fix_mtu(ctx, mtu)
    except SMError as e:
        # Handle error
        ctx.console.error(e.message)
        if e.details:
            for detail in e.details:
                ctx.console.print(f"  [dim]{detail}[/dim]")
        if e.hint:
            ctx.console.hint(e.hint)
        raise typer.Exit(e.exit_code)


@app.command("check-mtu")
def check_mtu_cmd(
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase output verbosity. Can be repeated (-v, -vv, -vvv).",
        ),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output.",
            is_flag=True,
        ),
    ] = False,
) -> None:
    """Check if Docker MTU fix is applied.

    Verifies that daemon.json has the correct MTU configuration and
    checks all existing overlay networks to see if they need recreation.

    [bold]What this checks:[/bold]
    - daemon.json has MTU configuration
    - Docker daemon is running
    - Existing overlay networks and their MTU values

    [bold]Examples:[/bold]

        # Check MTU configuration status
        sm docker check-mtu
    """
    from sm.commands.docker.network_mtu import run_check_mtu
    from sm.core.context import create_context
    from sm.core.exceptions import SMError

    ctx = create_context(
        dry_run=False,
        force=False,
        yes=False,
        verbose=verbose,
        no_color=no_color,
    )

    try:
        run_check_mtu(ctx)
    except SMError as e:
        ctx.console.error(e.message)
        if e.details:
            for detail in e.details:
                ctx.console.print(f"  [dim]{detail}[/dim]")
        if e.hint:
            ctx.console.hint(e.hint)
        raise typer.Exit(e.exit_code)


@app.command("list-networks")
def list_networks_cmd(
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase output verbosity. Can be repeated (-v, -vv, -vvv).",
        ),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output.",
            is_flag=True,
        ),
    ] = False,
) -> None:
    """List all Docker networks with their MTU values.

    Shows all Docker networks grouped by driver type, with their
    current MTU values and whether they need recreation.

    [bold]Examples:[/bold]

        # List all networks
        sm docker list-networks
    """
    from sm.commands.docker.network_mtu import run_list_networks
    from sm.core.context import create_context
    from sm.core.exceptions import SMError

    ctx = create_context(
        dry_run=False,
        force=False,
        yes=False,
        verbose=verbose,
        no_color=no_color,
    )

    try:
        run_list_networks(ctx)
    except SMError as e:
        ctx.console.error(e.message)
        if e.details:
            for detail in e.details:
                ctx.console.print(f"  [dim]{detail}[/dim]")
        if e.hint:
            ctx.console.hint(e.hint)
        raise typer.Exit(e.exit_code)


@app.command("recreate-network")
def recreate_network_cmd(
    network: Annotated[
        str,
        typer.Argument(
            help="Name of the network to recreate",
        ),
    ],
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force recreation even with connected containers.",
            is_flag=True,
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Skip confirmation prompts.",
            is_flag=True,
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Preview changes without executing.",
            is_flag=True,
        ),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Increase output verbosity. Can be repeated (-v, -vv, -vvv).",
        ),
    ] = 0,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output.",
            is_flag=True,
        ),
    ] = False,
) -> None:
    """Recreate a Docker network with proper MTU configuration.

    This command will:
    1. Check that daemon.json has MTU configuration
    2. Get the current network configuration
    3. Remove the old network
    4. Create a new network with the same settings but correct MTU

    [bold]WARNING:[/bold] This will disconnect all containers from the network.
    Make sure to stop containers first.

    [bold]Prerequisites:[/bold]
    - MTU fix must be applied (run: sudo sm docker fix-mtu)
    - No containers connected (or use --force)

    [bold]Examples:[/bold]

        # Preview network recreation
        sm docker recreate-network my_network --dry-run

        # Recreate network (will prompt for confirmation)
        sudo sm docker recreate-network my_network

        # Force recreation with connected containers
        sudo sm docker recreate-network my_network --force

        # Skip confirmation
        sudo sm docker recreate-network my_network -y
    """
    from sm.commands.docker.network_mtu import run_recreate_network
    from sm.core.context import create_context
    from sm.core.exceptions import SMError

    ctx = create_context(
        dry_run=dry_run,
        force=force,
        yes=yes,
        verbose=verbose,
        no_color=no_color,
    )

    try:
        run_recreate_network(ctx, network)
    except SMError as e:
        ctx.console.error(e.message)
        if e.details:
            for detail in e.details:
                ctx.console.print(f"  [dim]{detail}[/dim]")
        if e.hint:
            ctx.console.hint(e.hint)
        raise typer.Exit(e.exit_code)
