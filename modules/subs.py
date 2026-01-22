import os
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
from core.webhook import send_subdomain_notification, is_valid_webhook_url

module_key = "subs"
module_name = "Scans Default: subs.txt for new subodomains"
cli_name = "subs"


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
    parser.add_argument("--input_file", help="Input file with URLs/domains (defaults to subs.txt)")
    parser.add_argument("--ports", default="80,443", help="Ports for httpx")
    parser.add_argument("--threads", type=int, default=50, help="Threads for httpx")
    parser.add_argument("--rl", type=int, default=10, help="Rate limit for subfinder")
    parser.add_argument("--discord-webhook", action="store_true", help="Send Discord notifications (requires webhook file)")


def run_tui(stdscr, config):
    # Placeholder for TUI functionality
    pass


def run_cli(args, config):
    project_dir = ensure_project(args.project)
    history_dir = today_history_dir(project_dir)
    ensure_dir(history_dir)

    init_logger(project_dir,  module_name="subs")

    run_subs_discovery(project_dir, history_dir, args)

    close_logger()


def run_subs_discovery(project_dir, history_dir, args):
    """
    Enumerate subdomains for all URLs, check if they're alive, and append to alive.txt
    """
    # Input can be a file with URLs or domains
    input_file = getattr(args, 'input_file', None)
    if not input_file:
        # Default to using subs.txt as input if no specific input file provided
        input_file = os.path.join(project_dir, "subs.txt")
    
    if not os.path.exists(input_file):
        raise SystemExit(f"Missing input file: {input_file}")

    # Check required tools
    if not command_exists_with_installer("subfinder"):
        log_warn("subfinder not found; skipping subs discovery")
        return

    if not command_exists_with_installer("httpx"):
        log_warn("httpx not found; skipping subs discovery")
        return

    if not command_exists_with_installer("anew"):
        log_warn("anew not found; skipping subs discovery")
        return

    # Read input URLs/domains
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        targets = [x.strip() for x in f.readlines() if x.strip()]

    # Extract domains from URLs if needed
    domains = []
    for target in targets:
        if target.startswith("http"):
            # Extract domain from URL
            domain = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
        else:
            domain = target.strip()
        if domain:
            domains.append(domain)

    # Remove duplicates
    domains = list(set(domains))
    log_info(f"Enumerating subdomains for {len(domains)} domains")

    # Enumerate subdomains using subfinder
    all_subdomains = []
    subs_out_path = os.path.join(history_dir, "new_subdomains.txt")
    
    # Create temporary domain list for subfinder
    temp_domains_path = os.path.join(history_dir, "temp_domains.txt")
    write_lines(temp_domains_path, domains)
    
    cmd = [
        "subfinder",
        "-dL",
        temp_domains_path,
        "-all",
        "-recursive",
        "-o",
        subs_out_path,
        "-rl",
        str(getattr(args, 'rl', 10)),
    ]
    res = run_command(cmd, timeout=3600, apply_rate_limit=True)
    if res.returncode != 0:
        log_warn(f"subfinder rc={res.returncode}")
        if res.stderr:
            log_warn(res.stderr.strip()[:2000])
        return

    # Read enumerated subdomains
    if os.path.exists(subs_out_path):
        with open(subs_out_path, "r", encoding="utf-8", errors="ignore") as f:
            all_subdomains = [x.strip() for x in f.readlines() if x.strip()]

    if not all_subdomains:
        log_info("No subdomains found")
        return

    log_info(f"Found {len(all_subdomains)} subdomains, checking aliveness")

    # Use anew to append new subdomains to new_subs.txt in history folder
    history_subs_path = os.path.join(history_dir, "new_subs.txt")
    subs_shell_cmd = f"cat {subs_out_path} | anew {history_subs_path}"
    subs_anew_res = run_command(["bash", "-c", subs_shell_cmd], timeout=300)
    if subs_anew_res.returncode != 0:
        log_warn(f"anew (subdomains) rc={subs_anew_res.returncode}")
        if subs_anew_res.stderr:
            log_warn(subs_anew_res.stderr.strip()[:2000])
    else:
        log_info(f"Appended subdomains to {history_subs_path}")

# Check which subdomains are alive using httpx
    alive_out_path = os.path.join(history_dir, "new_alive.txt")
    alive_cmd = [
        "httpx",
        "-l",
        subs_out_path,
        "-ports",
        getattr(args, 'ports', '80,443'),
        "-threads",
        str(getattr(args, 'threads', 50)),
        "-o",
        alive_out_path,
    ]
    
    alive_res = run_command(alive_cmd, timeout=3600, apply_rate_limit=True)
    if alive_res.returncode != 0:
        log_warn(f"httpx rc={alive_res.returncode}")
        if alive_res.stderr:
            log_warn(alive_res.stderr.strip()[:2000])
        return

    # Read alive subdomains
    alive_subdomains = []
    if os.path.exists(alive_out_path):
        alive_subdomains = read_lines(alive_out_path)

    if not alive_subdomains:
        log_info("No alive subdomains found")
        return

    log_info(f"Found {len(alive_subdomains)} alive subdomains")

    # Use anew to append new alive subdomains to canonical alive.txt
    alive_txt_path = os.path.join(project_dir, "alive.txt")
    
    # Create temporary file with alive subdomains for anew
    temp_alive_path = os.path.join(history_dir, "temp_alive_for_anew.txt")
    write_lines(temp_alive_path, alive_subdomains)
    
    # Run anew with the alive subdomains file
    shell_cmd = f"cat {temp_alive_path} | anew {alive_txt_path}"
    anew_res = run_command(["bash", "-c", shell_cmd], timeout=300)
    if anew_res.returncode != 0:
        log_warn(f"anew rc={anew_res.returncode}")
        if anew_res.stderr:
            log_warn(anew_res.stderr.strip()[:2000])
        return

    # Log results
    log_ok(f"subs: +{len(alive_subdomains)} alive subdomains appended to {alive_txt_path}")

    # Send Discord notification if flag is passed
    discord_webhook_enabled = getattr(args, 'discord_webhook', False)
    if discord_webhook_enabled:
        # Read webhook URL from config file
        webhook_url = get_discord_webhook_url()
        if not webhook_url:
            log_warn("Discord webhook enabled but no valid webhook found in ~/.recon_discord")
        else:
            # Extract project name from path
            project_name = os.path.basename(project_dir.rstrip('/'))
            
            # Send notification
            success = send_subdomain_notification(
                webhook_url=webhook_url,
                project_name=project_name,
                new_subs_count=len(all_subdomains),
                new_alive_count=len(alive_subdomains),
                sample_subs=alive_subdomains[:5] if alive_subdomains else None
            )
            
            if success:
                log_info("Discord notification sent successfully")
            else:
                log_warn("Failed to send Discord notification")

                # working on discord integration