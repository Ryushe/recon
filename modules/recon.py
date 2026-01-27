import os
import os
import json
import urllib.parse
import urllib.request
from datetime import date

from core.runner import command_exists_with_installer, run_command, ensure_dir
from core.project import ensure_project, today_history_dir, merge_into_canonical, write_lines, read_lines
from core.logger import log_info, log_ok, log_warn, time_block, init_logger, close_logger
from core.rate_limiter import get_global_rate_limiter, configure_rate_limiter
from core.tools import ToolFactory
from core.webhook import send_directory_notification, send_secret_notification, send_vulnerability_notification, is_valid_webhook_url
from core.wordlist_manager import WordlistManager

module_name = "Run subfinder, crt.sh, httpx, dirsearch to find"
module_key = "1"
cli_name = "recon"


def get_discord_webhook_url():
    """Read Discord webhook URL from user's config file"""
    webhook_file = os.path.expanduser("~/.recon_discord")
    if os.path.exists(webhook_file):
        with open(webhook_file, "r", encoding="utf-8") as f:
            webhook_url = f.read().strip()
            if webhook_url and is_valid_webhook_url(webhook_url):
                return webhook_url
    return None


def register_args(parser):
    parser.add_argument("--project", required=True, help="Project directory (stateful)")
    parser.add_argument("--wildcard_list", default="wild.txt", help="Wildcard scope list inside project dir")
    parser.add_argument("--ports", default="443,80,8080,8000,8888", help="Ports for httpx")
    parser.add_argument("--threads", type=int, default=200, help="Threads for httpx/dirsearch where applicable")
    parser.add_argument("--full", action="store_true", help="Run full recon chain")

    parser.add_argument("--subs", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--alive", action="store_true", help="Run alive checking (httpx)")
    parser.add_argument("--ports_scan", action="store_true", help="Run naabu + nmap")
    parser.add_argument("--dirs", action="store_true", help="Run dirsearch")
    parser.add_argument("--params", action="store_true", help="Run gau + uro + js extraction")
    parser.add_argument("--secrets", action="store_true", help="Run SecretFinder on js list")
    parser.add_argument("--use_root_params", action="store_true", help="Use params.txt from root directory for SecretFinder")
    parser.add_argument("--nuclei", action="store_true", help="Run nuclei on filtered params")
    parser.add_argument("--screens", action="store_true", help="Run Eyewitness to capture screenshots")
    
    # Eyewitness specific arguments
    parser.add_argument("--eyewitness_args", help="Custom arguments to pass to Eyewitness (e.g., '--timeout 30 --no-dns')")
    parser.add_argument("--eyewitness_targets", choices=['all', 'latest'], default='latest', 
                       help="Target selection for Eyewitness: 'all' (all subs) or 'latest' (most recent alive file)")
    parser.add_argument("--eyewitness_file", help="Custom file with targets for Eyewitness")

    parser.add_argument("--secretfinder_path", default="$HOME/tools/SecretFinder/SecretFinder.py", help="Path to SecretFinder.py")
    parser.add_argument("--nuclei_templates", default="/usr/share/custom-nuclei", help="Nuclei templates path")
    parser.add_argument("--discord-webhook", action="store_true", help="Send Discord notifications (requires webhook file)")

    # Tool-specific rate limiting arguments
    parser.add_argument("--subfinder_rl", type=int, default=25, help="Subfinder rate limit (req/sec)")
    parser.add_argument("--httpx_rl", type=int, default=50, help="Httpx rate limit (req/sec)")
    parser.add_argument("--naabu_rl", type=int, default=100, help="Naabu rate limit (req/sec)")
    parser.add_argument("--nmap_rl", type=int, default=30, help="Nmap rate limit (req/sec)")
    parser.add_argument("--dirsearch_rl", type=int, default=20, help="Dirsearch rate limit (req/sec)")
    parser.add_argument("--gau_rl", type=int, default=15, help="GAU rate limit (req/sec)")
    parser.add_argument("--gau_timeout", type=int, default=600, help="GAU timeout in seconds (default: 600s = 10 minutes)")
    parser.add_argument("--uro_rl", type=int, default=15, help="URO rate limit (req/sec)")
    parser.add_argument("--nuclei_rl", type=int, default=30, help="Nuclei rate limit (req/sec)")
    parser.add_argument("--eyewitness_rl", type=int, default=10, help="Eyewitness rate limit (req/sec)")

    # Custom word list arguments
    parser.add_argument("--wordlist", help="Custom wordlist path for dirsearch")
    parser.add_argument("--wordlist_size", choices=['small', 'medium', 'large'], help="Predefined wordlist size for dirsearch")
    parser.add_argument("--wordlist_dir", help="Directory containing custom wordlists")


def run_tui(stdscr, config):
    stdscr.addstr(2, 2, "Use CLI for recon execution:")
    stdscr.addstr(4, 2, "python main.py recon --project ./target --full -v")
    stdscr.refresh()


def run_cli(args, config):
    project_dir = ensure_project(args.project)
    history_dir = today_history_dir(project_dir)

    init_logger(project_dir, module_name="recon")

    # Configure rate limiting (for tool-specific limits in config)
    configure_rate_limiter(config)

    # Check for required tools before proceeding
    from core.tool_installer import ToolInstaller
    installer = ToolInstaller()
    
    # Map steps to required tools
    step_tool_map = {
        "subs": ["subfinder"],
        "alive": ["httpx"],
        "ports_scan": ["naabu", "nmap"],
        "dirs": ["dirsearch"],
        "params": ["gau", "uro"],
        "secrets": ["secretfinder"],
        "nuclei": ["nuclei"],
        "screens": ["eyewitness"]
    }
    
    steps = resolve_steps(args)
    missing_tools = []
    
    for step in steps:
        required_tools = step_tool_map.get(step, [])
        for tool in required_tools:
            if not installer.check_tool_installed(tool):
                missing_tools.append(tool)
    
    if missing_tools:
        log_warn(f"Missing required tools: {', '.join(set(missing_tools))}")
        log_info("Run with --install-interactive to install missing tools")
        log_info("Or run with --install to install all tools")
        log_info("Or run with --check-tools to see detailed status")
        # Continue anyway - some tools might be available in PATH

    try:
        log_info(f"project_dir: {project_dir}")
        log_info(f"history_dir: {history_dir}")
        log_info(f"steps: {', '.join(sorted(list(steps)))}")

        if "subs" in steps:
            _run_wrapped("subs", run_subdomain_enum, project_dir, history_dir, args)

        if "alive" in steps:
            _run_wrapped("alive", run_alive_check, project_dir, history_dir, args)

        if "ports_scan" in steps:
            _run_wrapped("ports_scan", run_ports_scan, project_dir, history_dir, args)

        if "dirs" in steps:
            _run_wrapped("dirs", run_dirsearch, project_dir, history_dir, args)

        if "params" in steps:
            _run_wrapped("params", run_param_mining, project_dir, history_dir, args)

        if "secrets" in steps:
            _run_wrapped("secrets", run_secretfinder, project_dir, history_dir, args)

        if "nuclei" in steps:
            _run_wrapped("nuclei", run_nuclei, project_dir, history_dir, args)

        if "screens" in steps:
            _run_wrapped("screens", run_screenshots, project_dir, history_dir, args)

        meta_path = os.path.join(history_dir, "run_meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "project_dir": project_dir,
                    "history_dir": history_dir,
                    "steps": sorted(list(steps)),
                },
                f,
                indent=2,
            )

        log_ok(f"run_complete -> {history_dir}")

    finally:
        close_logger()


def _run_wrapped(step_name, fn, project_dir, history_dir, args):
    done = time_block(step_name)
    log_info(f"step_start: {step_name}")
    try:
        if args is None:
            fn(project_dir, history_dir)
        else:
            fn(project_dir, history_dir, args)
        log_ok(f"step_ok: {step_name}")
    except SystemExit:
        raise
    except Exception as e:
        log_warn(f"step_fail: {step_name} ({type(e).__name__}: {e})")
    finally:
        done()


def resolve_steps(args):
    if args.full:
        return {
            "subs",
            "alive",
            "ports_scan",
            "params",
            "secrets",
            "screens",
        }

    steps = set()
    if args.subs:
        steps.add("subs")
    if args.alive:
        steps.add("alive")
    if args.ports_scan:
        steps.add("ports_scan")
    if args.dirs:
        steps.add("dirs")
    if args.secrets:
        steps.add("params")
        steps.add("secrets")
    elif args.params:
        steps.add("params")
    if args.nuclei:
        steps.add("nuclei")
    if args.screens:
        steps.add("screens")

    if not steps:
        steps.add("subs")
        steps.add("alive")

    return steps


def get_wildcard_list_path(project_dir, wildcard_list_name):
    return os.path.join(project_dir, wildcard_list_name)


def fetch_crtsh_domains(domain):
    q = urllib.parse.quote(domain)
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "ryus-recon"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    names = []
    for item in data:
        nv = item.get("name_value", "")
        for part in str(nv).split("\n"):
            s = part.strip().lstrip("*.").strip()
            if s and " " not in s and "/" not in s:
                names.append(s)
    return names


def run_subdomain_enum(project_dir, history_dir, args):
    """Execute subdomain enumeration using SubfinderTool"""
    tool = ToolFactory.get_tool('subfinder')
    tool.run(project_dir, history_dir, args)


def run_alive_check(project_dir, history_dir, args):
    """Execute alive checking using HttpxTool"""
    tool = ToolFactory.get_tool('httpx')
    tool.run(project_dir, history_dir, args)


def run_ports_scan(project_dir, history_dir, args):
    """Execute port scanning using NaabuTool and NmapTool"""
    # Run naabu for port discovery on alive hosts
    # naabu_tool = ToolFactory.get_tool('naabu')
    # naabu_tool.run(project_dir, history_dir, args)
    
    # Run independent nmap for detailed scanning with incremental logic
    nmap_tool = ToolFactory.get_tool('nmap')
    nmap_tool.run(project_dir, history_dir, args)


def run_dirsearch(project_dir, history_dir, args):
    """Execute directory search using DirsearchTool"""
    tool = ToolFactory.get_tool('dirsearch')
    tool.run(project_dir, history_dir, args)


def run_param_mining(project_dir, history_dir, args):
    """Execute parameter mining using GauUroTool"""
    tool = ToolFactory.get_tool('gau_uro')
    tool.run(project_dir, history_dir, args)


def run_secretfinder(project_dir, history_dir, args):
    """Execute secret finding using SecretFinderTool"""
    tool = ToolFactory.get_tool('secretfinder')
    tool.run(project_dir, history_dir, args)


def run_nuclei(project_dir, history_dir, args):
    """Execute nuclei scanning using NucleiTool"""
    tool = ToolFactory.get_tool('nuclei')
    tool.run(project_dir, history_dir, args)


def run_screenshots(project_dir, history_dir, args):
    """Execute screenshot capture using EyewitnessTool"""
    from core.tools import EyewitnessTool
    tool = EyewitnessTool()
    tool.run(project_dir, history_dir, args)

