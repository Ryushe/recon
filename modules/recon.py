import os
import json
import urllib.parse
import urllib.request
from datetime import date

from core.runner import command_exists, command_exists_with_installer, run_command, ensure_dir
from core.project import (
    ensure_project,
    today_history_dir,
    merge_into_canonical,
    write_lines,
    read_lines,
)
from core.logger import log_info, log_ok, log_warn, time_block
from core.logger import init_logger, close_logger
from core.rate_limiter import get_global_rate_limiter, configure_rate_limiter
from core.wordlist_manager import WordlistManager
from core.webhook import send_directory_notification, send_secret_notification, send_vulnerability_notification, is_valid_webhook_url

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
    parser.add_argument("--rl", type=int, default=25, help="Rate limit for subfinder")
    parser.add_argument("--full", action="store_true", help="Run full recon chain")

    parser.add_argument("--subs", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--alive", action="store_true", help="Run alive checking (httpx)")
    parser.add_argument("--ports_scan", action="store_true", help="Run naabu + nmap")
    parser.add_argument("--dirs", action="store_true", help="Run dirsearch")
    parser.add_argument("--params", action="store_true", help="Run gau + uro + js extraction")
    parser.add_argument("--secrets", action="store_true", help="Run SecretFinder on js list")
    parser.add_argument("--nuclei", action="store_true", help="Run nuclei on filtered params")
    parser.add_argument("--screens", action="store_true", help="Placeholder for eyewitness")

    parser.add_argument("--secretfinder_path", default="$HOME/tools/SecretFinder/SecretFinder.py", help="Path to SecretFinder.py")
    parser.add_argument("--nuclei_templates", default="/usr/share/custom-nuclei", help="Nuclei templates path")
    parser.add_argument("--discord-webhook", action="store_true", help="Send Discord notifications (requires webhook file)")

    # Global rate limiting arguments
    parser.add_argument("--global_rps", type=int, help="Global requests per second (overrides config)")
    parser.add_argument("--disable_rate_limiting", action="store_true", help="Disable all rate limiting")

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

    # Configure rate limiting
    configure_rate_limiter(config)
    
    # Override global rate limiting if specified
    if args.global_rps:
        rate_limiter = get_global_rate_limiter()
        rate_limiter.set_global_rate(args.global_rps)
        log_info(f"Global rate limit overridden: {args.global_rps} RPS")
    
    # Disable rate limiting if requested
    if args.disable_rate_limiting:
        rate_limiter = get_global_rate_limiter()
        rate_limiter.disable()
        log_info("Rate limiting disabled")

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
        "nuclei": ["nuclei"]
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
            _run_wrapped("screens", run_screenshots_placeholder, project_dir, history_dir, args=None)

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
            "dirs",
            "params",
            "secrets",
            "nuclei",
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
    if args.params:
        steps.add("params")
    if args.secrets:
        steps.add("secrets")
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
    ensure_dir(history_dir)

    wild_path = get_wildcard_list_path(project_dir, args.wildcard_list)
    if not os.path.exists(wild_path):
        raise SystemExit(f"Missing wildcard list: {wild_path}")

    combined_candidates = []

    if command_exists_with_installer("subfinder"):
        out_path = os.path.join(history_dir, "subfinder_subs.txt")
        cmd = [
            "subfinder",
            "-dL",
            wild_path,
            "-all",
            "-recursive",
            "-o",
            out_path,
            "-rl",
            str(args.rl),
        ]
        res = run_command(cmd, timeout=3600, apply_rate_limit=True)
        if res.returncode != 0:
            log_warn(f"subfinder rc={res.returncode}")
            if res.stderr:
                log_warn(res.stderr.strip()[:2000])

        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                combined_candidates.extend([x.strip() for x in f.readlines() if x.strip()])
    else:
        log_warn("subfinder not found; skipping subfinder stage")

    with open(wild_path, "r", encoding="utf-8", errors="ignore") as f:
        wild_targets = [x.strip() for x in f.readlines() if x.strip()]

    crt_out = os.path.join(history_dir, "crt_subs.txt")
    crt_lines = []
    for d in wild_targets:
        try:
            crt_lines.extend(fetch_crtsh_domains(d))
        except Exception as e:
            log_warn(f"crt.sh fetch failed for {d}: {e}")

    write_lines(crt_out, crt_lines)
    combined_candidates.extend(crt_lines)

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="subs.txt",
        candidate_lines=combined_candidates,
        history_dir=history_dir,
        delta_file_name="new_subs.txt",
    )
    log_ok(f"subs: +{merged['new_count']} new -> {merged['delta_path']}")


def run_alive_check(project_dir, history_dir, args):
    subs_path = os.path.join(project_dir, "subs.txt")
    if not os.path.exists(subs_path):
        raise SystemExit("Missing subs.txt; run --subs first")

    if not command_exists_with_installer("httpx"):
        log_warn("httpx not found; skipping alive stage")
        return

    # Check if this is the first run by looking for existing alive files
    alive_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                         if os.path.exists(os.path.join(project_dir, "history", d, "httpx_alive.txt"))]
    
    if alive_history_dirs and len(alive_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in alive_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_alive = os.path.join(project_dir, "history", previous_dir, "httpx_alive.txt")
            previously_alive = set()
            
            if os.path.exists(previous_alive):
                previously_alive = set(read_lines(previous_alive))
            
            # Get all existing subs and filter out those already checked
            all_subs = read_lines(subs_path)
            new_subs = [sub for sub in all_subs if sub not in previously_alive]
            
            if not new_subs:
                log_info("No new subdomains to check for aliveness")
                return
                
            # Create temporary file with new subs only
            temp_subs_path = os.path.join(history_dir, "new_subs.txt")
            write_lines(temp_subs_path, new_subs)
            target_subs_path = temp_subs_path
            log_info(f"Checking {len(new_subs)} new subdomains for aliveness")
        else:
            target_subs_path = subs_path
    else:
        # First run - check all subs
        target_subs_path = subs_path
        log_info("First alive check run - checking all subdomains")

    out_path = os.path.join(history_dir, "httpx_alive.txt")
    cmd = [
        "httpx",
        "-l",
        target_subs_path,
        "-ports",
        args.ports,
        "-threads",
        str(args.threads),
    ]
    res = run_command(cmd, timeout=3600, apply_rate_limit=True)
    if res.returncode != 0:
        log_warn(f"httpx rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])

    lines = res.stdout.splitlines() if res.stdout else []
    write_lines(out_path, lines)

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="alive.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_alive.txt",
    )
    log_ok(f"alive: +{merged['new_count']} new -> {merged['delta_path']}")


def run_ports_scan(project_dir, history_dir, args):
    subs_path = os.path.join(project_dir, "subs.txt")
    if not os.path.exists(subs_path):
        raise SystemExit("Missing subs.txt; run --subs first")

    if not command_exists_with_installer("naabu"):
        log_warn("naabu not found; skipping ports scan")
        return

    # Check if this is the first run by looking for existing port scan files
    ports_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                         if os.path.exists(os.path.join(project_dir, "history", d, "naabu_ports.txt"))]
    
    if ports_history_dirs and len(ports_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in ports_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_ports = os.path.join(project_dir, "history", previous_dir, "naabu_ports.txt")
            previously_scanned = set()
            
            if os.path.exists(previous_ports):
                # Extract hosts from previous port scan results
                with open(previous_ports, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        try:
                            data = json.loads(line)
                            host = data.get("host", "")
                            if host:
                                previously_scanned.add(host)
                        except json.JSONDecodeError:
                            continue
            
            # Get all existing subs and filter out those already scanned
            all_subs = read_lines(subs_path)
            new_subs = [sub for sub in all_subs if sub not in previously_scanned]
            
            if not new_subs:
                log_info("No new subdomains to scan for ports")
                return
                
            # Create temporary file with new subs only
            temp_subs_path = os.path.join(history_dir, "new_subs_for_ports.txt")
            write_lines(temp_subs_path, new_subs)
            target_subs_path = temp_subs_path
            log_info(f"Scanning {len(new_subs)} new subdomains for ports")
        else:
            target_subs_path = subs_path
    else:
        # First run - scan all subs
        target_subs_path = subs_path
        log_info("First port scan run - scanning all subdomains")

    out_path = os.path.join(history_dir, "naabu_ports.txt")
    cmd = [
        "naabu",
        "-list",
        target_subs_path,
        "-ports",
        "-",
        "-c",
        "50",
        "-silent",
        "-json",
        "-o",
        out_path,
    ]
    res = run_command(cmd, timeout=1800)
    if res.returncode != 0:
        log_warn(f"naabu rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])
        return

    ports = set()
    if os.path.exists(out_path):
        for line in open(out_path):
            try:
                data = json.loads(line.strip())
                ports.add(str(data.get("port", "")))
            except json.JSONDecodeError:
                continue

    if ports:
        ports_str = ",".join(sorted(ports))
    else:
        ports_str = "80,443"

    if not command_exists_with_installer("nmap"):
        log_warn("nmap not found; skipping ports stage")
        return

    out_path = os.path.join(history_dir, "naabu_full.txt")
    cmd = [
        "naabu",
        "-list",
        target_subs_path,
        "-c",
        "50",
        "-nmap-cli",
        "nmap -sV -sC",
        "-o",
        out_path,
    ]
    res = run_command(cmd, timeout=6 * 3600)
    if res.returncode != 0:
        log_warn(f"naabu rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [x.strip() for x in f.readlines() if x.strip()]
    else:
        lines = []

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="ports.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_ports.txt",
    )
    log_ok(f"ports: +{merged['new_count']} new -> {merged['delta_path']}")


def run_dirsearch(project_dir, history_dir, args):
    alive_path = os.path.join(project_dir, "alive.txt")
    if not os.path.exists(alive_path):
        raise SystemExit("Missing alive.txt; run --alive first")

    if not command_exists_with_installer("dirsearch"):
        log_warn("dirsearch not found; skipping dirs stage")
        return

    # Check if this is the first run by looking for existing dirsearch files
    dirsearch_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                             if os.path.exists(os.path.join(project_dir, "history", d, "dirsearch.txt"))]
    
    if dirsearch_history_dirs and len(dirsearch_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in dirsearch_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_dirs_file = os.path.join(project_dir, "history", previous_dir, "dirsearch.txt")
            previously_scanned = set()
            
            if os.path.exists(previous_dirs_file):
                # Extract hosts from previous dirsearch results
                with open(previous_dirs_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Extract host from URL if present
                            if "http" in line:
                                host = line.split("://")[1].split("/")[0].strip()
                                if host:
                                    previously_scanned.add(host)
            
            # Get all existing alive URLs and filter out those already scanned
            all_alive = read_lines(alive_path)
            new_alive = []
            for url in all_alive:
                host = url.replace("https://", "").replace("http://", "").split("/")[0].strip()
                if host and host not in previously_scanned:
                    new_alive.append(url)
            
            if not new_alive:
                log_info("No new alive hosts to scan for directories")
                return
                
            # Create temporary file with new alive URLs only
            temp_alive_path = os.path.join(history_dir, "new_alive_for_dirs.txt")
            write_lines(temp_alive_path, new_alive)
            target_alive_path = temp_alive_path
            log_info(f"Scanning {len(new_alive)} new alive hosts for directories")
        else:
            target_alive_path = alive_path
    else:
        # First run - scan all alive URLs
        target_alive_path = alive_path
        log_info("First directory scan run - scanning all alive URLs")

    out_path = os.path.join(history_dir, "dirsearch.txt")
    
    # Use wordlist manager to get the appropriate wordlist
    wordlist_manager = WordlistManager()
    try:
        if args.wordlist:
            wordlist = wordlist_manager.get_wordlist(custom_path=args.wordlist)
        elif args.wordlist_size:
            wordlist = wordlist_manager.get_wordlist(args.wordlist_size)
        else:
            wordlist = wordlist_manager.get_wordlist()
        
        # Validate the wordlist
        if not wordlist_manager.validate_wordlist(wordlist):
            log_warn(f"Wordlist validation failed: {wordlist}")
            return
            
    except FileNotFoundError as e:
        log_warn(f"Wordlist not found: {e}")
        return

    cmd = [
        "dirsearch",
        "-l",
        target_alive_path,
        "-x",
        "600,502,439,404,400",
        "-R",
        "5",
        "--random-agent",
        "-t",
        "100",
        "-F",
        "-o",
        out_path,
        "-w",
        wordlist,
    ]
    res = run_command(cmd, timeout=6 * 3600, apply_rate_limit=True)
    if res.returncode != 0:
        log_warn(f"dirsearch rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [x.rstrip("\n") for x in f.readlines()]
    else:
        lines = []

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="dirs.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_dirs.txt",
    )
    log_ok(f"dirs: +{merged['new_count']} new -> {merged['delta_path']}")

    # Send Discord notification if flag is passed and new directories found
    discord_webhook_enabled = getattr(args, 'discord_webhook', False)
    if discord_webhook_enabled and merged['new_count'] > 0:
        webhook_url = get_discord_webhook_url()
        if not webhook_url:
            log_warn("Discord webhook enabled but no valid webhook found in ~/.recon_discord")
        else:
            project_name = os.path.basename(project_dir.rstrip('/'))
            
            # Get sample directories for notification
            sample_dirs = []
            if os.path.exists(merged['delta_path']):
                with open(merged['delta_path'], "r", encoding="utf-8", errors="ignore") as f:
                    sample_dirs = [line.strip() for line in f.readlines()[:5] if line.strip()]
            
            success = send_directory_notification(
                webhook_url=webhook_url,
                project_name=project_name,
                new_dirs_count=merged['new_count'],
                sample_dirs=sample_dirs
            )
            
            if success:
                log_info("Discord directory notification sent")


def run_param_mining(project_dir, history_dir, args):
    alive_path = os.path.join(project_dir, "alive.txt")
    if not os.path.exists(alive_path):
        raise SystemExit("Missing alive.txt; run --alive first")

    if not command_exists_with_installer("gau"):
        log_warn("gau not found; skipping params stage")
        return

    if not command_exists_with_installer("uro"):
        log_warn("uro not found; skipping params stage")
        return

    # Get only new alive URLs for this run
    existing_alive = read_lines(os.path.join(project_dir, "alive.txt"))
    
    # Check if this is the first run by looking for existing params files
    params_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                          if os.path.exists(os.path.join(project_dir, "history", d, "params_raw.txt"))]
    
    if params_history_dirs and len(params_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in params_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_params = os.path.join(project_dir, "history", previous_dir, "params_raw.txt")
            previously_processed_urls = set()
            
            # Extract unique hosts from previous params to avoid reprocessing
            if os.path.exists(previous_params):
                with open(previous_params, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            # Extract host from URL
                            host = line.replace("https://", "").replace("http://", "").split("/")[0].strip()
                            if host:
                                previously_processed_urls.add(host)
            
            # Only process alive URLs whose hosts weren't processed before
            new_hosts = []
            for url in existing_alive:
                host = url.replace("https://", "").replace("http://", "").split("/")[0].strip()
                if host and host not in previously_processed_urls:
                    new_hosts.append(url)
            
            if not new_hosts:
                log_info("No new alive hosts to process for param mining")
                return
                
            # Create temporary file with new URLs only
            temp_alive_path = os.path.join(history_dir, "new_alive.txt")
            write_lines(temp_alive_path, new_hosts)
            target_alive_path = temp_alive_path
            log_info(f"Processing {len(new_hosts)} new alive hosts for param mining")
        else:
            target_alive_path = alive_path
    else:
        # First run - process all alive URLs
        target_alive_path = alive_path
        log_info("First param mining run - processing all alive URLs")

    # Run gau on target URLs: cat [target] | gau
    shell_cmd = f"cat {target_alive_path} | gau"
    gau_res = run_command(["bash", "-c", shell_cmd], timeout=120, apply_rate_limit=True)
    if gau_res.returncode != 0:
        log_warn(f"gau failed with return code {gau_res.returncode}")
        return
    
    all_urls = gau_res.stdout.splitlines() if gau_res.stdout else []

    raw_params_path = os.path.join(history_dir, "params_raw.txt")
    write_lines(raw_params_path, all_urls)

    tmp_in = os.path.join(history_dir, "uro_in.txt")
    with open(tmp_in, "w", encoding="utf-8") as f:
        for u in all_urls:
            if u and str(u).strip():
                f.write(str(u).strip() + "\n")

    uro_out = os.path.join(history_dir, "params_filtered.txt")
    res = run_command(["uro", "-i", tmp_in, "-o", uro_out], timeout=600, apply_rate_limit=True)
    if res.returncode != 0:
        log_warn(f"uro rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])

    if os.path.exists(uro_out):
        with open(uro_out, "r", encoding="utf-8", errors="ignore") as f:
            filtered = [x.strip() for x in f.readlines() if x.strip()]
    else:
        filtered = []

    merged_params = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="params.txt",
        candidate_lines=filtered,
        history_dir=history_dir,
        delta_file_name="new_params.txt",
    )
    log_ok(f"params: +{merged_params['new_count']} new -> {merged_params['delta_path']}")

    js = [u for u in filtered if u.lower().endswith(".js")]
    merged_js = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="js.txt",
        candidate_lines=js,
        history_dir=history_dir,
        delta_file_name="new_js.txt",
    )
    log_ok(f"js: +{merged_js['new_count']} new -> {merged_js['delta_path']}")


def run_secretfinder(project_dir, history_dir, args):
    js_path = os.path.join(project_dir, "js.txt")
    if not os.path.exists(js_path):
        raise SystemExit("Missing js.txt; run --params first")

    if not command_exists("python3"):  # Keep basic check for python3
        log_warn("python3 not found; skipping secrets stage")
        return

    secretfinder_path = args.secretfinder_path
    if not os.path.exists(secretfinder_path):
        log_warn(f"SecretFinder not found at {secretfinder_path}; skipping secrets stage")
        return

    # Check if this is the first run by looking for existing secretfinder files
    secretfinder_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                                 if os.path.exists(os.path.join(project_dir, "history", d, "secrets.txt"))]
    
    if secretfinder_history_dirs and len(secretfinder_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in secretfinder_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_secrets = os.path.join(project_dir, "history", previous_dir, "secrets.txt")
            previously_scanned = set()
            
            if os.path.exists(previous_secrets):
                # Extract URLs from previous secretfinder results
                with open(previous_secrets, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and "http" in line:
                            # Extract URL from the line (assuming format contains the URL)
                            parts = line.split()
                            for part in parts:
                                if part.startswith("http"):
                                    previously_scanned.add(part)
                                    break
            
            # Get all existing JS URLs and filter out those already scanned
            all_js = read_lines(js_path)
            new_js = [js for js in all_js if js not in previously_scanned]
            
            if not new_js:
                log_info("No new JS URLs to scan for secrets")
                return
                
            log_info(f"Scanning {len(new_js)} new JS URLs for secrets")
        else:
            new_js = read_lines(js_path)
            log_info("First secrets scan run - scanning all JS URLs")
    else:
        # First run - scan all JS URLs
        new_js = read_lines(js_path)
        log_info("First secrets scan run - scanning all JS URLs")

    findings = []
    for url in new_js:
        cmd = ["python3", secretfinder_path, "-i", url, "-o", "cli"]
        res = run_command(cmd, timeout=120)
        if res.returncode != 0:
            log_warn(f"SecretFinder rc={res.returncode} url={url}")
            continue

        if res.stdout:
            findings.extend([x.rstrip("\n") for x in res.stdout.splitlines() if x.strip()])

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="secrets.txt",
        candidate_lines=findings,
        history_dir=history_dir,
        delta_file_name="new_secrets.txt",
    )
    log_ok(f"secrets: +{merged['new_count']} new -> {merged['delta_path']}")

    # Send Discord notification if flag is passed and new secrets found
    discord_webhook_enabled = getattr(args, 'discord_webhook', False)
    if discord_webhook_enabled and merged['new_count'] > 0:
        webhook_url = get_discord_webhook_url()
        if not webhook_url:
            log_warn("Discord webhook enabled but no valid webhook found in ~/.recon_discord")
        else:
            project_name = os.path.basename(project_dir.rstrip('/'))
            
            # Get sample secrets for notification
            sample_secrets = []
            if os.path.exists(merged['delta_path']):
                with open(merged['delta_path'], "r", encoding="utf-8", errors="ignore") as f:
                    sample_secrets = [line.strip() for line in f.readlines()[:3] if line.strip()]
            
            success = send_secret_notification(
                webhook_url=webhook_url,
                project_name=project_name,
                new_secrets_count=merged['new_count'],
                sample_secrets=sample_secrets
            )
            
            if success:
                log_info("Discord secrets notification sent")


def run_nuclei(project_dir, history_dir, args):
    params_path = os.path.join(project_dir, "params.txt")
    if not os.path.exists(params_path):
        raise SystemExit("Missing params.txt; run --params first")

    if not command_exists_with_installer("nuclei"):
        log_warn("nuclei not found; skipping nuclei stage")
        return

    # Check if this is the first run by looking for existing nuclei files
    nuclei_history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                         if os.path.exists(os.path.join(project_dir, "history", d, "nuclei.txt"))]
    
    if nuclei_history_dirs and len(nuclei_history_dirs) > 1:
        # Find the previous run directory (excluding today)
        today = date.today().isoformat()
        previous_dirs = [d for d in nuclei_history_dirs if d != today]
        if previous_dirs:
            previous_dir = max(previous_dirs)  # Get the most recent previous run
            previous_nuclei = os.path.join(project_dir, "history", previous_dir, "nuclei.txt")
            previously_scanned = set()
            
            if os.path.exists(previous_nuclei):
                # Extract hosts from previous nuclei results
                with open(previous_nuclei, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("["):
                            # Extract host from URL if present
                            if "http" in line:
                                host = line.split("://")[1].split("/")[0].strip()
                                if host:
                                    previously_scanned.add(host)
            
            # Get all existing params and filter out those already scanned
            all_params = read_lines(params_path)
            new_params = []
            for param in all_params:
                host = param.replace("https://", "").replace("http://", "").split("/")[0].strip()
                if host and host not in previously_scanned:
                    new_params.append(param)
            
            if not new_params:
                log_info("No new params to scan with nuclei")
                return
                
            # Create temporary file with new params only
            temp_params_path = os.path.join(history_dir, "new_params.txt")
            write_lines(temp_params_path, new_params)
            target_params_path = temp_params_path
            log_info(f"Scanning {len(new_params)} new params with nuclei")
        else:
            target_params_path = params_path
    else:
        # First run - scan all params
        target_params_path = params_path
        log_info("First nuclei scan run - scanning all params")

    out_path = os.path.join(history_dir, "nuclei.txt")
    cmd = [
        "nuclei",
        "-list",
        target_params_path,
        "-c",
        "70",
        "-rl",
        "200",
        "-fhr",
        "-lfa",
        "-t",
        args.nuclei_templates,
        "-o",
        out_path,
        "-es",
        "info",
    ]
    res = run_command(cmd, timeout=6 * 3600, apply_rate_limit=True)
    if res.returncode != 0:
        log_warn(f"nuclei rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [x.rstrip("\n") for x in f.readlines()]
    else:
        lines = []

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="nuclei.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_nuclei.txt",
    )
    log_ok(f"nuclei: +{merged['new_count']} new -> {merged['delta_path']}")


def run_screenshots_placeholder(project_dir, history_dir):
    note_path = os.path.join(history_dir, "screenshots_note.txt")
    write_lines(note_path, ["eyewitness stage not implemented yet"])
    log_ok("screens: placeholder written (eyewitness integration next)")

