import argparse
import curses

from core.config import load_config
from core.plugin_loader import load_modules
from core.tui import run_tui
from core.logger import set_verbose_level
from core.tool_installer import install_tools_all, install_tools_interactive, ToolInstaller


def build_parser(modules):
    parser = argparse.ArgumentParser(prog="ryus_recon")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-vv for debug)")
    parser.add_argument("--install", action="store_true", help="Install all required tools")
    parser.add_argument("--install-interactive", action="store_true", help="Interactively install missing tools")
    parser.add_argument("--check-tools", action="store_true", help="Check installation status of tools")

    subparsers = parser.add_subparsers(dest="command")

    for _, module in modules.items():
        if "register_args" in module and callable(module["register_args"]):
            module_parser = subparsers.add_parser(module["cli_name"], help=module["name"])
            module_parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-vv for debug)")
            module["register_args"](module_parser)

    return parser


def run_cli(args, modules, config):
    set_verbose_level(args.verbose)

    command = args.command
    for _, module in modules.items():
        if module.get("cli_name") == command:
            if "run_cli" not in module or not callable(module["run_cli"]):
                raise SystemExit(f"Module '{command}' does not support cli mode")
            module["run_cli"](args, config)
            return

    raise SystemExit(f"Unknown command: {command}")


def main():
    config = load_config()
    modules = load_modules()

    parser = build_parser(modules)
    args = parser.parse_args()
    
    set_verbose_level(args.verbose)

    # Handle installation flags
    if args.install:
        install_tools_all()
        return
    elif args.install_interactive:
        install_tools_interactive()
        return
    elif args.check_tools:
        installer = ToolInstaller(config)
        status = installer.list_tools_status()
        
        installed_count = sum(1 for s in status.values() if s['installed'])
        total_count = len(status)
        
        print(f"\nTool Installation Status: {installed_count}/{total_count}")
        print("=" * 50)
        
        for tool_name, info in status.items():
            status_str = "✓" if info['installed'] else "✗"
            print(f"  {status_str} {tool_name} ({info['type']})")
        
        missing = installer.get_missing_tools()
        if missing:
            print(f"\nMissing tools: {', '.join(missing)}")
            print("Run with --install-interactive to install them.")
        return

    if args.command:
        run_cli(args, modules, config)
        return

    def tui_entry(stdscr):
        curses.curs_set(0)
        run_tui(stdscr, modules, config)

    curses.wrapper(tui_entry)


if __name__ == "__main__":
    main()

