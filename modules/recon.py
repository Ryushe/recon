import os
import json
import urllib.parse
import urllib.request

from core.runner import command_exists, run_command, ensure_dir
from core.project import (
    ensure_project,
    today_history_dir,
    merge_into_canonical,
    write_lines,
)

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


def run_tui(stdscr, config):
    stdscr.addstr(2, 2, "Use CLI for recon execution:")
    stdscr.addstr(4, 2, "python main.py recon --project ./target --full")
    stdscr.refresh()


def run_cli(args, config):
    project_dir = ensure_project(args.project)
    history_dir = today_history_dir(project_dir)

    steps = resolve_steps(args)

    if "subs" in steps:
        run_subdomain_enum(project_dir, history_dir, args)

    if "alive" in steps:
        run_alive_check(project_dir, history_dir, args)

    if "ports_scan" in steps:
        run_ports_scan(project_dir, history_dir, args)

    if "dirs" in steps:
        run_dirsearch(project_dir, history_dir, args)

    if "params" in steps:
        run_param_mining(project_dir, history_dir, args)

    if "secrets" in steps:
        run_secretfinder(project_dir, history_dir, args)

    if "nuclei" in steps:
        run_nuclei(project_dir, history_dir, args)

    if "screens" in steps:
        run_screenshots_placeholder(project_dir, history_dir)

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

    print(f"[+] Done. History: {history_dir}")


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
    candidate = os.path.join(project_dir, wildcard_list_name)
    return candidate


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

    if command_exists("subfinder"):
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
        res = run_command(cmd, timeout=3600)
        if res.returncode != 0:
            print(res.stderr.strip())

        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                combined_candidates.extend([x.strip() for x in f.readlines()])
    else:
        print("[!] subfinder not found; skipping subfinder stage")

    with open(wild_path, "r", encoding="utf-8", errors="ignore") as f:
        wild_targets = [x.strip() for x in f.readlines() if x.strip()]

    crt_out = os.path.join(history_dir, "crt_subs.txt")
    crt_lines = []
    for d in wild_targets:
        try:
            crt_lines.extend(fetch_crtsh_domains(d))
        except Exception as e:
            print(f"[!] crt.sh fetch failed for {d}: {e}")
    write_lines(crt_out, crt_lines)
    combined_candidates.extend(crt_lines)

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="subs.txt",
        candidate_lines=combined_candidates,
        history_dir=history_dir,
        delta_file_name="new_subs.txt",
    )
    print(f"[+] subs: +{merged['new_count']} new -> {merged['delta_path']}")


def run_alive_check(project_dir, history_dir, args):
    subs_path = os.path.join(project_dir, "subs.txt")
    if not os.path.exists(subs_path):
        raise SystemExit("Missing subs.txt; run --subs first")

    if not command_exists("httpx-toolkit"):
        print("[!] httpx-toolkit not found; skipping alive stage")
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
    res = run_command(cmd, timeout=3600)
    if res.returncode != 0:
        print(res.stderr.strip())

    lines = res.stdout.splitlines()
    write_lines(out_path, lines)

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="alive.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_alive.txt",
    )
    print(f"[+] alive: +{merged['new_count']} new -> {merged['delta_path']}")


def run_ports_scan(project_dir, history_dir, args):
    subs_path = os.path.join(project_dir, "subs.txt")
    if not os.path.exists(subs_path):
        raise SystemExit("Missing subs.txt; run --subs first")

    if not command_exists("naabu"):
        print("[!] naabu not found; skipping ports stage")
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
        print(res.stderr.strip())

    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [x.strip() for x in f.readlines()]
    else:
        lines = []

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="ports.txt",
        candidate_lines=lines,
        history_dir=history_dir,
        delta_file_name="new_ports.txt",
    )
    print(f"[+] ports: +{merged['new_count']} new -> {merged['delta_path']}")


def run_dirsearch(project_dir, history_dir, args):
    alive_path = os.path.join(project_dir, "alive.txt")
    if not os.path.exists(alive_path):
        raise SystemExit("Missing alive.txt; run --alive first")

    if not command_exists("dirsearch"):
        print("[!] dirsearch not found; skipping dirs stage")
        return

    out_path = os.path.join(history_dir, "dirsearch.txt")
    wordlist = "/usr/share/wordlists/OneListForAll/onelistforallshort.txt"

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
    res = run_command(cmd, timeout=6 * 3600)
    if res.returncode != 0:
        print(res.stderr.strip())

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
    print(f"[+] dirs: +{merged['new_count']} new -> {merged['delta_path']}")


def run_param_mining(project_dir, history_dir, args):
    alive_path = os.path.join(project_dir, "alive.txt")
    if not os.path.exists(alive_path):
        raise SystemExit("Missing alive.txt; run --alive first")

    if not command_exists("gau"):
        print("[!] gau not found; skipping params stage")
        return
    if not command_exists("uro"):
        print("[!] uro not found; skipping params stage")
        return

    gau_res = run_command(["gau", "--providers", "wayback,commoncrawl,otx,urlscan", "--threads", "10"], timeout=3600)
    # note: gau by default expects domains via stdin; we’ll feed it ourselves per alive host below (simple + safe)
    # we will do a minimal approach: run gau per host
    with open(alive_path, "r", encoding="utf-8", errors="ignore") as f:
        alive_urls = [x.strip() for x in f.readlines() if x.strip()]

    all_urls = []
    for url in alive_urls:
        host = url.replace("https://", "").replace("http://", "").split("/")[0].strip()
        if not host:
            continue
        res = run_command(["gau", host], timeout=120)
        if res.returncode == 0 and res.stdout:
            all_urls.extend(res.stdout.splitlines())

    raw_params_path = os.path.join(history_dir, "params_raw.txt")
    write_lines(raw_params_path, all_urls)

    # uro filter
    uro_in = "\n".join(all_urls).encode("utf-8", errors="ignore")
    # subprocess wrapper uses list cmd; easiest: write tmp + call uro on file
    tmp_in = os.path.join(history_dir, "uro_in.txt")
    with open(tmp_in, "wb") as f:
        f.write(uro_in)

    uro_out = os.path.join(history_dir, "params_filtered.txt")
    res = run_command(["uro", "-i", tmp_in, "-o", uro_out], timeout=600)
    if res.returncode != 0:
        print(res.stderr.strip())

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
    print(f"[+] params: +{merged_params['new_count']} new -> {merged_params['delta_path']}")

    js = [u for u in filtered if u.lower().endswith(".js")]
    merged_js = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="js.txt",
        candidate_lines=js,
        history_dir=history_dir,
        delta_file_name="new_js.txt",
    )
    print(f"[+] js: +{merged_js['new_count']} new -> {merged_js['delta_path']}")


def run_secretfinder(project_dir, history_dir, args):
    js_path = os.path.join(project_dir, "js.txt")
    if not os.path.exists(js_path):
        raise SystemExit("Missing js.txt; run --params first")

    if not command_exists("python3"):
        print("[!] python3 not found; skipping secrets stage")
        return

    secretfinder_path = args.secretfinder_path
    if not os.path.exists(secretfinder_path):
        print(f"[!] SecretFinder not found at {secretfinder_path}; skipping secrets stage")
        return

    with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
        js_urls = [x.strip() for x in f.readlines() if x.strip()]

    findings = []
    for url in js_urls:
        cmd = ["python3", secretfinder_path, "-i", url, "-o", "cli"]
        res = run_command(cmd, timeout=120)
        if res.returncode == 0 and res.stdout:
            findings.extend([x.rstrip("\n") for x in res.stdout.splitlines() if x.strip()])

    merged = merge_into_canonical(
        project_dir=project_dir,
        canonical_file="secrets.txt",
        candidate_lines=findings,
        history_dir=history_dir,
        delta_file_name="new_secrets.txt",
    )
    print(f"[+] secrets: +{merged['new_count']} new -> {merged['delta_path']}")


def run_nuclei(project_dir, history_dir, args):
    params_path = os.path.join(project_dir, "params.txt")
    if not os.path.exists(params_path):
        raise SystemExit("Missing params.txt; run --params first")

    if not command_exists("nuclei"):
        print("[!] nuclei not found; skipping nuclei stage")
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
    res = run_command(cmd, timeout=6 * 3600)
    if res.returncode != 0:
        print(res.stderr.strip())

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
    print(f"[+] nuclei: +{merged['new_count']} new -> {merged['delta_path']}")


def run_screenshots_placeholder(project_dir, history_dir):
    note_path = os.path.join(history_dir, "screenshots_note.txt")
    write_lines(note_path, ["eyewitness stage not implemented yet"])
    print("[+] screens: placeholder written (eyewitness integration next)")

