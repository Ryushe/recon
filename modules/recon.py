import os
import json
import urllib.parse
import urllib.request

from core.runner import command_exists, command_exists_with_installer, run_command, ensure_dir
from core.project import (
    ensure_project,
    today_history_dir,
    merge_into_canonical,
    write_lines,
)
from core.logger import log_info, log_ok, log_warn, time_block
from core.logger import init_logger, close_logger
from core.rate_limiter import get_global_rate_limiter, configure_rate_limiter
from core.wordlist_manager import WordlistManager

module_name = "Recon"
module_key = "1"
cli_name = "recon"


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

    parser.add_argument("--secretfinder_path", default="SecretFinder.py", help="Path to SecretFinder.py")
    parser.add_argument("--nuclei_templates", default="/opt/Custom-Nuclei-Templates", help="Nuclei templates path")

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
        "alive": ["httpx-toolkit"],
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

    if not command_exists_with_installer("httpx-toolkit"):
        log_warn("httpx-toolkit not found; skipping alive stage")
        return

    out_path = os.path.join(history_dir, "httpx_alive.txt")
    cmd = [
        "httpx-toolkit",
        "-l",
        subs_path,
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

    out_path = os.path.join(history_dir, "naabu_ports.txt")
    cmd = [
        "naabu",
        "-list",
        subs_path,
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
        subs_path,
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
        alive_path,
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

    with open(alive_path, "r", encoding="utf-8", errors="ignore") as f:
        alive_urls = [x.strip() for x in f.readlines() if x.strip()]

    all_urls = []
    for url in alive_urls:
        host = url.replace("https://", "").replace("http://", "").split("/")[0].strip()
        if not host:
            continue

        res = run_command(["gau", host], timeout=120, apply_rate_limit=True)
        if res.returncode != 0:
            log_warn(f"gau rc={res.returncode} host={host}")
            continue

        if res.stdout:
            all_urls.extend(res.stdout.splitlines())

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

    with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
        js_urls = [x.strip() for x in f.readlines() if x.strip()]

    findings = []
    for url in js_urls:
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


def run_nuclei(project_dir, history_dir, args):
    params_path = os.path.join(project_dir, "params.txt")
    if not os.path.exists(params_path):
        raise SystemExit("Missing params.txt; run --params first")

    if not command_exists_with_installer("nuclei"):
        log_warn("nuclei not found; skipping nuclei stage")
        return

    out_path = os.path.join(history_dir, "nuclei.txt")
    cmd = [
        "nuclei",
        "-list",
        params_path,
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

