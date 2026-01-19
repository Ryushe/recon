import argparse
import curses

from core.config import load_config
from core.plugin_loader import load_modules
from core.tui import run_tui
from core.logger import set_verbose_level


def build_parser(modules):
    parser = argparse.ArgumentParser(prog="ryus_recon")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-vv for debug)")

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

    if args.command:
        run_cli(args, modules, config)
        return

    def tui_entry(stdscr):
        curses.curs_set(0)
        run_tui(stdscr, modules, config)

    curses.wrapper(tui_entry)


if __name__ == "__main__":
    main()

