import argparse
import curses

from core.config import load_config
from core.plugin_loader import load_modules
from core.tui import run_tui
from core.logger import set_verbose_level
from core.tool_installer import install_tools_all, install_tools_interactive, ToolInstaller
from core.single_url import setup_single_url_mode, cleanup_temp_directory


def build_parser(modules):
    parser = argparse.ArgumentParser(prog="ryus_recon")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-vv for debug)")
    parser.add_argument("--install", action="store_true", help="Install all required tools")
    parser.add_argument("--install-interactive", action="store_true", help="Interactively install missing tools")
    parser.add_argument("--check-tools", action="store_true", help="Check installation status of tools")
    parser.add_argument("--url", help="Single URL mode - create temp directory and run recon on specified URL")

    subparsers = parser.add_subparsers(dest="command")

    for _, module in modules.items():
        if "register_args" in module and callable(module["register_args"]):
            module_parser = subparsers.add_parser(module["cli_name"], help=module["name"])
            module_parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-vv for debug)")
            module["register_args"](module_parser)

    return parser


def run_cli(args, modules, config, command=None):
    set_verbose_level(args.verbose)

    if command is None:
        command = getattr(args, 'command', None)
    
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

    # Handle single URL mode
    temp_dir = None
    original_command = args.command
    
    if args.url:
        temp_dir = setup_single_url_mode(args.url, args, config)
        
        # If no command specified, default to recon with --full
        if not args.command:
            original_command = "recon"
            # Create a simple namespace object for recon args
            class ReconArgs:
                def __init__(self):
                    self.project = temp_dir
                    self.url = None
                    self.full = True
                    self.verbose = args.verbose
                    self.threads = 200
                    self.ports = "443,80,8080,8000,8888"
                    self.wildcard_list = "wild.txt"
                    self.subs = False
                    self.alive = False
                    self.ports_scan = False
                    self.dirs = False
                    self.params = False
                    self.secrets = False
                    self.use_root_params = False
                    self.nuclei = False
                    self.screens = False
                    self.secretfinder_path = "$HOME/tools/SecretFinder/SecretFinder.py"
                    self.nuclei_templates = "/usr/share/custom-nuclei"
                    self.discord_webhook = False
                    # Rate limiting args
                    self.subfinder_rl = 25
                    self.httpx_rl = 50
                    self.naabu_rl = 100
                    self.nmap_rl = 30
                    self.dirsearch_rl = 20
                    self.gau_rl = 15
                    self.gau_timeout = 600
                    self.uro_rl = 15
                    self.nuclei_rl = 30
                    self.eyewitness_rl = 10
                    # Wordlist args
                    self.wordlist = None
                    self.wordlist_size = None
                    self.wordlist_dir = None
                    # Eyewitness args
                    self.eyewitness_args = None
                    self.eyewitness_targets = "latest"
                    self.eyewitness_file = None
            
            args = ReconArgs()
        else:
            # If a command was specified, just update the project directory
            args.project = temp_dir

    if original_command:
        try:
            run_cli(args, modules, config, original_command)
        finally:
            # Clean up temp directory if single URL mode was used
            if temp_dir:
                cleanup_temp_directory(temp_dir)
        return

    def tui_entry(stdscr):
        curses.curs_set(0)
        run_tui(stdscr, modules, config)

    curses.wrapper(tui_entry)


if __name__ == "__main__":
    main()

