"""
Tool execution module - Centralized external tool command execution
"""

import os
from datetime import date
from core.runner import run_command, command_exists_with_installer
from core.project import merge_into_canonical, write_lines, read_lines
from core.logger import log_info, log_ok, log_warn, time_block
from core.webhook import send_directory_notification, send_secret_notification, send_vulnerability_notification, is_valid_webhook_url


class BaseTool:
    """Base class for all tool execution with common patterns"""
    
    def __init__(self, name):
        self.name = name
        
    def check_tool_exists(self):
        """Check if tool is available and attempt installation if missing"""
        if not command_exists_with_installer(self.name):
            log_warn(f"{self.name} not found; skipping {self.name} stage")
            return False
        return True
    
    def should_skip(self, project_dir, history_dir, skip_file=None):
        """Check if tool should be skipped based on existing results"""
        if skip_file and os.path.exists(skip_file):
            log_info(f"{self.name}: skipping - {skip_file} exists")
            return True
        return False
    
    def execute_command(self, cmd, timeout=600, rate_limit=None):
        """Execute command with tool-specific rate limiting"""
        log_info(f"Running: {' '.join(cmd)}")
        
        # Apply rate limiting if specified
        if rate_limit is not None:
            from core.rate_limiter import get_global_rate_limiter
            limiter = get_global_rate_limiter()
            limiter.set_tool_limit(self.name, rate_limit)
            log_info(f"{self.name}: Using rate limit {rate_limit} RPS")
            res = run_command(cmd, timeout=timeout, apply_rate_limit=True)
        else:
            res = run_command(cmd, timeout=timeout, apply_rate_limit=False)
        
        if res.returncode != 0:
            log_warn(f"{self.name} failed with return code {res.returncode}")
            if res.stderr:
                log_warn(f"{self.name} stderr: {res.stderr}")
            return None
            
        return res
    
    def process_results(self, project_dir, history_dir, results, canonical_file, delta_file_name):
        """Process tool results using standard merge pattern"""
        merged = merge_into_canonical(
            project_dir=project_dir,
            canonical_file=canonical_file,
            candidate_lines=results,
            history_dir=history_dir,
            delta_file_name=delta_file_name,
        )
        log_ok(f"{self.name}: +{merged['new_count']} new -> {merged['delta_path']}")
        return merged


class SubfinderTool(BaseTool):
    """Subfinder execution and CRT.sh domain fetching"""
    
    def __init__(self):
        super().__init__("subfinder")
    
    def fetch_crtsh_domains(self, domain):
        """Fetch domains from crt.sh"""
        import json
        import urllib.parse
        import urllib.request
        
        q = urllib.parse.quote(domain)
        url = f"https://crt.sh/?q={q}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ryus-recon"})
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        
        try:
            data = json.loads(raw)
            domains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split():
                    if name and "*" not in name:
                        domains.add(name.lower().strip())
            return sorted(domains)
        except json.JSONDecodeError:
            return []
    
    def run(self, project_dir, history_dir, args):
        """Execute subfinder with CRT.sh integration"""
        if not self.check_tool_exists():
            return
        
        all_domains = []
        
        # Get existing canonical domains
        canonical_path = os.path.join(project_dir, "canonical.txt")
        existing_domains = set()
        if os.path.exists(canonical_path):
            existing_domains = set(read_lines(canonical_path))
        
        # Get wildcard list path
        from core.project import get_wildcard_list_path
        wild_path = get_wildcard_list_path(project_dir, args.wildcard_list)
        if not os.path.exists(wild_path):
            raise SystemExit(f"Missing wildcard list: {wild_path}")
        
        # Run subfinder with wildcard list
        log_info("Running subfinder with wildcard list")
        cmd = [
            "subfinder", "-dL", wild_path,
            "-all", "-recursive",
            "-o", os.path.join(history_dir, "subfinder_subs.txt"),
            "-rl", str(args.subfinder_rl)
        ]
        
        # Get rate limit from args and execute
        rate_limit = getattr(args, 'subfinder_rl', None)
        res = self.execute_command(cmd, rate_limit=rate_limit)
        if res:
            subfinder_path = os.path.join(history_dir, "subfinder_subs.txt")
            if os.path.exists(subfinder_path):
                subfinder_domains = read_lines(subfinder_path)
                all_domains.extend(subfinder_domains)
        
        # Fetch from crt.sh for wildcard targets
        log_info("Fetching from crt.sh")
        wild_targets = read_lines(wild_path)
        for target_domain in wild_targets:
            crtsh_domains = self.fetch_crtsh_domains(target_domain)
            all_domains.extend(crtsh_domains)
        
        # Remove duplicates and existing domains
        new_domains = list(set(all_domains) - existing_domains)
        
        if new_domains:
            subdomains_path = os.path.join(history_dir, "subdomains.txt")
            write_lines(subdomains_path, new_domains)
            
            merged = self.process_results(project_dir, history_dir, new_domains, "subs.txt", "new_subs.txt")
            
            # Discord notification
            if merged['new_count'] > 0:
                webhook_file = os.path.expanduser("~/.recon_discord")
                if os.path.exists(webhook_file) and is_valid_webhook_url(webhook_file):
                    project_name = os.path.basename(project_dir.rstrip('/'))
                    send_directory_notification(webhook_file, project_name, merged['delta_path'], merged['new_count'])


class HttpxTool(BaseTool):
    """Httpx for alive host checking"""
    
    def __init__(self):
        super().__init__("httpx")
    
    def get_incremental_targets(self, project_dir, history_dir):
        """Get new subs to check (avoid rechecking)"""
        existing_alive = set()
        alive_path = os.path.join(project_dir, "alive.txt")
        if os.path.exists(alive_path):
            existing_alive = set(read_lines(alive_path))
        
        # Get subs from today and merge into canonical
        today_subs = os.path.join(history_dir, "subdomains.txt")
        if os.path.exists(today_subs):
            subs = read_lines(today_subs)
            self.process_results(project_dir, history_dir, subs, "subs.txt", "new_subs.txt")
        
        # Check previous runs to find already processed hosts
        history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                       if os.path.exists(os.path.join(project_dir, "history", d, "httpx_raw.txt"))]
        
        if len(history_dirs) > 1:
            today = date.today().isoformat()
            previous_dirs = [d for d in history_dirs if d != today]
            if previous_dirs:
                previous_dir = max(previous_dirs)
                previous_httpx = os.path.join(project_dir, "history", previous_dir, "httpx_raw.txt")
                if os.path.exists(previous_httpx):
                    previously_checked = set(read_lines(previous_httpx))
                    all_subs = set(read_lines(os.path.join(project_dir, "subs.txt")))
                    return list(all_subs - previously_checked)
        
        return read_lines(os.path.join(project_dir, "subs.txt"))
    
    def run(self, project_dir, history_dir, args):
        """Execute httpx alive checking"""
        if not self.check_tool_exists():
            return
        
        targets = self.get_incremental_targets(project_dir, history_dir)
        if not targets:
            log_info("No new targets to check")
            return
        
        temp_targets_path = os.path.join(history_dir, "targets_httpx.txt")
        write_lines(temp_targets_path, targets)
        
        cmd = [
            "httpx", "-l", temp_targets_path,
            "-o", os.path.join(history_dir, "httpx_raw.txt"),
            "-threads", "200", "-ports", "443,80,8080,8000,8888"
        ]
        
        if hasattr(args, 'threads') and args.threads:
            cmd.extend(["-threads", str(args.threads)])
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'httpx_rl', None)
        res = self.execute_command(cmd, rate_limit=rate_limit, timeout=1200)
        if not res:
            return
        
        # Parse JSON results and extract URLs
        import json
        alive_urls = []
        httpx_raw_path = os.path.join(history_dir, "httpx_raw.txt")
        if os.path.exists(httpx_raw_path):
            with open(httpx_raw_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get("status_code") and 200 <= data["status_code"] < 600:
                                if data.get("status_code") and 200 <= data["status_code"] < 600:
                                    alive_urls.append(data["url"])
                        except json.JSONDecodeError:
                            continue
        
        if alive_urls:
            self.process_results(project_dir, history_dir, alive_urls, "alive.txt", "new_alive.txt")


class NaabuTool(BaseTool):
    """Naabu port scanning tool"""
    
    def __init__(self):
        super().__init__("naabu")
    
    def run(self, project_dir, history_dir, args):
        """Execute naabu port scan with skip logic"""
        if not self.check_tool_exists():
            return
        
        # Check for manual skip file
        if self.should_skip(project_dir, history_dir, "naabu_complete.txt"):
            log_info("Naabu: manually skipped - naabu_complete.txt exists")
            return
        
        alive_file = os.path.join(project_dir, "alive.txt")
        if not os.path.exists(alive_file):
            log_warn("No alive.txt file found for port scanning")
            return
        
        cmd = [
            "naabu", "-l", alive_file,
            "-o", os.path.join(history_dir, "naabu_raw.txt"),
            "-json", "-silent",
            "-p", "1-65535"
        ]
        
        if hasattr(args, 'threads') and args.threads:
            cmd.extend(["-c", str(args.threads)])
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'naabu_rl', None)
        res = self.execute_command(cmd, rate_limit=rate_limit, timeout=1800)
        if not res:
            return
        
        # Parse naabu JSON results
        import json
        ports = []
        naabu_raw_path = os.path.join(history_dir, "naabu_raw.txt")
        if os.path.exists(naabu_raw_path):
            with open(naabu_raw_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            host = data.get("host")
                            port = data.get("port")
                            if host and port:
                                ports.append(f"{host}:{port}")
                        except json.JSONDecodeError:
                            continue
        
        if ports:
            merged = self.process_results(project_dir, history_dir, ports, "ports.txt", "new_ports.txt")
            log_ok(f"naabu: +{len(ports)} new ports -> {merged['delta_path']}")


class NmapTool(BaseTool):
    """Nmap detailed scanning tool with incremental two-pass scanning"""
    
    def __init__(self):
        super().__init__("nmap")
    
    def get_incremental_hosts(self, project_dir, history_dir):
        """Get hosts to scan (avoid re-scanning)"""
        # Get alive hosts to scan
        alive_hosts = set()
        alive_file = os.path.join(project_dir, "alive.txt")
        if os.path.exists(alive_file):
            alive_hosts = set(read_lines(alive_file))
        
        # Check for previous nmap scans to avoid re-scanning
        history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                       if os.path.exists(os.path.join(project_dir, "history", d, "nmap_raw.xml"))]
        
        if len(history_dirs) > 1:
            today = date.today().isoformat()
            previous_dirs = [d for d in history_dirs if d != today]
            if previous_dirs:
                previous_dir = max(previous_dirs)
                previous_nmap = os.path.join(project_dir, "history", previous_dir, "nmap_raw.xml")
                previously_scanned = set()
                
                if os.path.exists(previous_nmap):
                    import xml.etree.ElementTree as ET
                    try:
                        tree = ET.parse(previous_nmap)
                        root = tree.getroot()
                        for host in root.findall(".//host"):
                            address = host.find(".//address[@addrtype='ipv4']")
                            if address is not None:
                                ip = address.get("addr")
                                if ip:
                                    previously_scanned.add(ip)
                    except:
                        pass  # If XML parsing fails, just scan all
                
                # Only scan hosts not previously scanned
                new_hosts = [host for host in alive_hosts if host not in previously_scanned]
                log_info(f"Nmap incremental: scanning {len(new_hosts)} new hosts (skipping {len(alive_hosts) - len(new_hosts)} previously scanned)")
                return new_hosts
        
        # First run - scan all alive hosts
        log_info(f"Nmap first run: scanning all {len(alive_hosts)} alive hosts")
        return list(alive_hosts)
    
    def run(self, project_dir, history_dir, args):
        """Execute two-pass nmap scanning with skip logic"""
        if not self.check_tool_exists():
            return
        
        # Check for manual skip files
        if self.should_skip(project_dir, history_dir, "nmap_quick.xml"):
            log_info("Nmap: manually skipped - nmap_quick.xml exists")
            return
        if self.should_skip(project_dir, history_dir, "nmap_intense.xml"):
            log_info("Nmap: manually skipped - nmap_intense.xml exists") 
            return
        
        # Get hosts to scan (with incremental logic)
        hosts = self.get_incremental_hosts(project_dir, history_dir)
        if not hosts:
            log_info("No new hosts to scan with nmap")
            return
        
        hosts_file = os.path.join(history_dir, "hosts_for_nmap.txt")
        # Remove http:// and https:// prefixes from hosts
        cleaned_hosts = [host.replace("https://", "").replace("http://", "") for host in hosts]
        write_lines(hosts_file, cleaned_hosts)
        
        # Define interesting ports for quick scan
        interesting_ports = ['8080', '8443', '8888', '8000', '8081']
        
        # First pass: Quick scan on interesting ports
        log_info("Nmap pass 1: Quick scan on interesting ports")
        quick_cmd = [
            "nmap", "-iL", hosts_file,
            "-oX", os.path.join(history_dir, "nmap_quick.xml"),
            "-oN", os.path.join(history_dir, "nmap_quick.txt"),
            "-T4", "-p", ",".join(interesting_ports),
            "--open", "-v"
        ]
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'nmap_rl', None)
        quick_res = self.execute_command(quick_cmd, timeout=1800, rate_limit=rate_limit)  # 30 minutes
        if not quick_res:
            log_warn("Quick nmap scan failed")
            return
        
        # Parse quick scan results to find hosts with open ports
        hosts_with_ports = set()
        quick_xml_path = os.path.join(history_dir, "nmap_quick.xml")
        if os.path.exists(quick_xml_path):
            import xml.etree.ElementTree as ET
            tree = ET.parse(quick_xml_path)
            root = tree.getroot()
            for host in root.findall(".//host"):
                address = host.find(".//address[@addrtype='ipv4']")
                if address is not None:
                    ip = address.get("addr")
                    # Check if any ports are open
                    open_ports = host.findall(".//port/state[@state='open']")
                    if open_ports:
                        hosts_with_ports.add(ip)
        
        if not hosts_with_ports:
            log_info("No hosts with open ports found in quick scan")
            return
        
        # Second pass: Intense scan only on hosts with open ports
        log_info(f"Nmap pass 2: Intense scan on {len(hosts_with_ports)} hosts with open ports")
        intense_hosts_file = os.path.join(history_dir, "hosts_with_ports.txt")
        write_lines(intense_hosts_file, list(hosts_with_ports))
        
        intense_cmd = [
            "nmap", "-iL", intense_hosts_file,
            "-oX", os.path.join(history_dir, "nmap_intense.xml"),
            "-oN", os.path.join(history_dir, "nmap_intense.txt"),
            "-sV", "-sC", 
            "-T3", "-p", "1-65535"
        ]
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'nmap_rl', None)
        intense_res = self.execute_command(intense_cmd, timeout=3600, rate_limit=rate_limit)  # 60 minutes
        if not intense_res:
            log_warn("Intense nmap scan failed")
            return
        
        # Parse intense scan results for final output
        services = []
        intense_xml_path = os.path.join(history_dir, "nmap_intense.xml")
        if os.path.exists(intense_xml_path):
            import xml.etree.ElementTree as ET
            tree = ET.parse(intense_xml_path)
            root = tree.getroot()
            
            for host in root.findall(".//host"):
                address = host.find(".//address[@addrtype='ipv4']")
                if address is not None:
                    ip = address.get("addr")
                    for port in host.findall(".//port"):
                        if port.find(".//state[@state='open']") is not None:
                            port_id = port.get("portid")
                            service = port.find(".//service")
                            service_name = service.get("name") if service is not None else "unknown"
                            services.append(f"{ip}:{port_id} ({service_name})")
        
        if services:
            merged = self.process_results(project_dir, history_dir, services, "services.txt", "new_services.txt")
            log_info(f"Nmap completed: {merged['new_count']} new services from {len(hosts_with_ports)} hosts with open ports")
            
            # Create completion markers
            quick_complete = os.path.join(history_dir, "nmap_quick.xml")
            intense_complete = os.path.join(history_dir, "nmap_intense.xml")
            with open(quick_complete, "w") as f:
                f.write("nmap quick scan completed")
            with open(intense_complete, "w") as f:
                f.write("nmap intense scan completed")
        else:
            log_info("Nmap completed: No new services found")


class DirsearchTool(BaseTool):
    """Dirsearch directory busting tool"""
    
    def __init__(self):
        super().__init__("dirsearch")
    
    def run(self, project_dir, history_dir, args):
        """Execute dirsearch with incremental scanning"""
        if not self.check_tool_exists():
            return
        
        alive_file = os.path.join(project_dir, "alive.txt")
        if not os.path.exists(alive_file):
            log_warn("No alive.txt file found for directory searching")
            return
        
        # Handle incremental runs to avoid re-scanning
        history_dirs = [d for d in os.listdir(os.path.join(project_dir, "history")) 
                       if os.path.exists(os.path.join(project_dir, "history", d, "dirsearch_raw.txt"))]
        
        if len(history_dirs) > 1:
            today = date.today().isoformat()
            previous_dirs = [d for d in history_dirs if d != today]
            if previous_dirs:
                previous_dir = max(previous_dirs)
                previous_dirsearch = os.path.join(project_dir, "history", previous_dir, "dirsearch_raw.txt")
                if os.path.exists(previous_dirsearch):
                    previously_scanned = set(read_lines(previous_dirsearch))
                    all_alive = set(read_lines(alive_file))
                    new_targets = list(all_alive - previously_scanned)
                    
                    if new_targets:
                        temp_alive_path = os.path.join(history_dir, "new_alive.txt")
                        write_lines(temp_alive_path, new_targets)
                        target_alive_path = temp_alive_path
                        log_info(f"Processing {len(new_targets)} new alive hosts for directory search")
                    else:
                        log_info("No new alive hosts to process for directory search")
                        return
                else:
                    target_alive_path = alive_file
            else:
                target_alive_path = alive_file
        else:
            target_alive_path = alive_file
        
        # Build dirsearch command
        cmd = [
            "dirsearch", "-l", target_alive_path,
            "-x", "600,502,439,404,400",
            "-R", "5", "--random-agent", "-t", "100", "-F",
            "-o", os.path.join(history_dir, "dirsearch_raw.txt")
        ]
        
        # Get wordlist
        from core.wordlist_manager import WordlistManager
        wordlist_mgr = WordlistManager()
        wordlist_path = wordlist_mgr.get_wordlist(
            list_type=getattr(args, 'wordlist_size', 'medium'),
            custom_path=getattr(args, 'wordlist', None)
        )
        
        # Add wordlist
        if wordlist_path:
            cmd.extend(["-w", wordlist_path])
        
        # Add custom arguments if provided
        if hasattr(args, 'wordlist_args') and args.wordlist_args:
            custom_args = args.wordlist_args.split()
            cmd.extend(custom_args)
        
        # Set rate limiting (conservative default for dirsearch)
        cmd.extend(["--threads=20", "--timeout=10", "--retries=1"])
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'dirsearch_rl', None)
        res = self.execute_command(cmd, timeout=2400, rate_limit=rate_limit)  # 40 minutes
        if not res:
            return
        
        # Process dirsearch results
        directories = []
        dirsearch_raw_path = os.path.join(history_dir, "dirsearch_raw.txt")
        if os.path.exists(dirsearch_raw_path):
            with open(dirsearch_raw_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and "http" in line and not line.startswith("="):
                        directories.append(line)
        
        if directories:
            merged = self.process_results(project_dir, history_dir, directories, "directories.txt", "new_directories.txt")
            
            # Discord notification for interesting findings
            if merged['new_count'] > 0:
                webhook_file = os.path.expanduser("~/.recon_discord")
                if os.path.exists(webhook_file) and is_valid_webhook_url(webhook_file):
                    send_directory_notification(webhook_file, "directory_search", merged['delta_path'], merged['new_count'])


class GauUroTool(BaseTool):
    """GAU and URO parameter mining tool"""
    
    def __init__(self):
        super().__init__("gau")  # Primary tool for checking
    
    def run(self, project_dir, history_dir, args):
        """Execute GAU + URO parameter mining"""
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
                              if os.path.exists(os.path.join(project_dir, "history", d, "params.txt"))]
        
        if params_history_dirs and len(params_history_dirs) > 1:
            today = date.today().isoformat()
            previous_dirs = [d for d in params_history_dirs if d != today]
            if previous_dirs:
                previous_dir = max(previous_dirs)
                previous_params = os.path.join(project_dir, "history", previous_dir, "params.txt")
                previously_processed_urls = set()
                
                if os.path.exists(previous_params):
                    with open(previous_params, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                host = line.replace("https://", "").replace("http://", "").split("/")[0].strip()
                                if host:
                                    previously_processed_urls.add(host)
                
                new_hosts = []
                for url in existing_alive:
                    host = url.replace("https://", "").replace("http://", "").split("/")[0].strip()
                    if host and host not in previously_processed_urls:
                        new_hosts.append(url)
                
                if not new_hosts:
                    log_info("No new alive hosts to process for param mining")
                    return
                    
                temp_alive_path = os.path.join(history_dir, "new_alive.txt")
                write_lines(temp_alive_path, new_hosts)
                target_alive_path = temp_alive_path
                log_info(f"Processing {len(new_hosts)} new alive hosts for param mining")
            else:
                target_alive_path = os.path.join(project_dir, "alive.txt")
        else:
            target_alive_path = os.path.join(project_dir, "alive.txt")
            log_info("First param mining run - processing all alive URLs")
        
        # Run gau to collect URLs with parameters directly to output file
        params_path = os.path.join(history_dir, "params.txt")
        shell_cmd = f"cat {target_alive_path} | gau > {params_path}"
        log_info("Running GAU to collect URLs with parameters")
        # Get rate limit and timeout from args
        gau_rate_limit = getattr(args, 'gau_rl', None)
        gau_timeout = getattr(args, 'gau_timeout', 600)  # Default 10 minutes
        
        log_info(f"GAU: Using timeout {gau_timeout}s and rate limit {gau_rate_limit} RPS")
        
        # Execute GAU with specified timeout
        gau_res = run_command(["bash", "-c", shell_cmd], timeout=gau_timeout, rate_limit=gau_rate_limit)
        if gau_res.returncode != 0:
            log_warn(f"gau failed with return code {gau_res.returncode}")
            return
        
        # Read the output file to get count for logging and process results
        all_urls = read_lines(params_path) if os.path.exists(params_path) else []
        log_info(f"GAU collected {len(all_urls)} URLs")
        
        # Process raw GAU results to create global file in root directory
        if all_urls:
            raw_merged = self.process_results(project_dir, history_dir, all_urls, "gau_raw.txt", "new_gau_raw.txt")
        
        # Run URO to filter parameters from GAU output
        uro_out = os.path.join(history_dir, "params_filtered.txt")
        log_info("Running URO to filter URLs with parameters")
        
        # Get URO rate limit
        uro_rate_limit = getattr(args, 'uro_rl', None)
        uro_timeout = getattr(args, 'uro_timeout', 600)  # Default 10 minutes
        
        log_info(f"URO: Using timeout {uro_timeout}s and rate limit {uro_rate_limit} RPS")
        
        # Execute URO with rate limit and timeout
        res = run_command(["uro", "-i", params_path, "-o", uro_out], timeout=uro_timeout, rate_limit=uro_rate_limit)
        if res.returncode != 0:
            log_warn(f"uro rc={res.returncode}")
            if res.stderr:
                log_warn(res.stderr.strip()[:2000])
            return
        
        if os.path.exists(uro_out):
            params = read_lines(uro_out)
            log_info(f"URO filtered to {len(params)} parameterized URLs")
            if params:
                # Process parameterized URLs
                merged = self.process_results(project_dir, history_dir, params, "params.txt", "new_params.txt")
                
                # Extract JavaScript URLs for SecretFinder
                js_urls = [u for u in params if u.lower().endswith(".js")]
                if js_urls:
                    js_merged = self.process_results(project_dir, history_dir, js_urls, "js.txt", "new_js.txt")
                    log_info(f"Extracted {js_merged['new_count']} new JavaScript URLs")


class SecretFinderTool(BaseTool):
    """SecretFinder JavaScript analysis tool"""
    
    def __init__(self):
        super().__init__("python3")  # Check for Python instead
    
    def run(self, project_dir, history_dir, args):
        """Execute SecretFinder on JavaScript files"""
        from core.runner import command_exists
        
        secretfinder_path = getattr(args, 'secretfinder_path', None) or "$HOME/tools/SecretFinder/SecretFinder.py"
        
        if not command_exists("python3"):
            log_warn("python3 not found; skipping secrets stage")
            return
        
        expanded_path = os.path.expandvars(os.path.expanduser(secretfinder_path))
        if not os.path.exists(expanded_path):
            log_warn(f"SecretFinder not found at {expanded_path}; skipping secrets stage")
            return
        
        # Use root params file by default, allow flag to use history params
        use_root_params = getattr(args, 'use_root_params', False)
        if use_root_params:
            params_file = os.path.join(project_dir, "params.txt")
        else:
            params_file = os.path.join(history_dir, "params.txt")
        if not os.path.exists(params_file):
            log_warn("No params.txt found; skipping secrets stage")
            return
        
        # Extract JavaScript URLs from params
        js_urls = []
        for line in read_lines(params_file):
            if line.strip().endswith('.js'):
                js_urls.append(line.strip())
        
        if not js_urls:
            log_info("No JavaScript URLs found in params.txt")
            return
        
        js_file_path = os.path.join(history_dir, "js_urls.txt")
        write_lines(js_file_path, js_urls)
        
        cmd = [
            "python3", expanded_path,
            "-i", js_file_path,
            "-o", os.path.join(history_dir, "secrets_raw.txt")
        ]
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'nuclei_rl', None)
        res = self.execute_command(cmd, timeout=1200, rate_limit=rate_limit)
        if res.returncode != 0:
            log_warn(f"SecretFinder rc={res.returncode}")
            if res.stderr:
                log_warn(res.stderr.strip()[:2000])
            return
        
        if os.path.exists(os.path.join(history_dir, "secrets_raw.txt")):
            secrets = read_lines(os.path.join(history_dir, "secrets_raw.txt"))
            if secrets:
                merged = self.process_results(project_dir, history_dir, secrets, "secrets.txt", "new_secrets.txt")
                
                # Discord notification for secrets
                if merged['new_count'] > 0:
                    webhook_file = os.path.expanduser("~/.recon_discord")
                    if os.path.exists(webhook_file) and is_valid_webhook_url(webhook_file):
                        send_secret_notification(webhook_file, "secrets_found", merged['delta_path'], merged['new_count'])


class NucleiTool(BaseTool):
    """Nuclei vulnerability scanning tool"""
    
    def __init__(self):
        super().__init__("nuclei")
    
    def run(self, project_dir, history_dir, args):
        """Execute Nuclei on filtered parameters"""
        params_file = os.path.join(project_dir, "params.txt")
        if not os.path.exists(params_file):
            log_warn("No params.txt found; skipping nuclei stage")
            return
        
        cmd = [
            "nuclei", "-l", params_file,
            "-o", os.path.join(history_dir, "nuclei_raw.txt"),
            "-json", "-silent"
        ]
        
        # Add custom templates if specified
        templates_path = getattr(args, 'nuclei_templates', None)
        if templates_path and os.path.exists(templates_path):
            cmd.extend(["-t", templates_path])
        
        # Get rate limit and execute
        rate_limit = getattr(args, 'nuclei_rl', None)
        res = self.execute_command(cmd, timeout=2400, rate_limit=rate_limit)
        if res.returncode != 0:
            log_warn(f"Nuclei failed with return code {res.returncode}")
            if res.stderr:
                log_warn(res.stderr.strip()[:2000])
            return
        
        # Parse nuclei JSON results
        import json
        vulnerabilities = []
        nuclei_raw_path = os.path.join(history_dir, "nuclei_raw.txt")
        if os.path.exists(nuclei_raw_path):
            with open(nuclei_raw_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get("matched-at"):
                                vulnerability = f"{data.get('matched-at')} - {data.get('info', {}).get('name', 'unknown')}"
                                vulnerabilities.append(vulnerability)
                        except json.JSONDecodeError:
                            continue
        
        if vulnerabilities:
            merged = self.process_results(project_dir, history_dir, vulnerabilities, "vulnerabilities.txt", "new_vulnerabilities.txt")
            
            # Discord notification for vulnerabilities
            if merged['new_count'] > 0:
                webhook_file = os.path.expanduser("~/.recon_discord")
                if os.path.exists(webhook_file) and is_valid_webhook_url(webhook_file):
                    send_vulnerability_notification(webhook_file, "nuclei_scan", merged['delta_path'], merged['new_count'])


class EyewitnessTool(BaseTool):
    """Eyewitness screenshot capture tool"""
    
    def __init__(self):
        super().__init__("eyewitness")
    
    def run(self, project_dir, history_dir, args):
        """Execute Eyewitness with configurable targets"""
        if not self.check_tool_exists():
            return
        
        # Determine target file based on user preferences
        target_file = None
        
        if hasattr(args, 'eyewitness_file') and args.eyewitness_file:
            if not os.path.exists(args.eyewitness_file):
                log_warn(f"Custom eyewitness file not found: {args.eyewitness_file}")
                return
            target_file = args.eyewitness_file
            log_info(f"Using custom target file: {args.eyewitness_file}")
        elif hasattr(args, 'eyewitness_targets') and args.eyewitness_targets == 'all':
            subs_file = os.path.join(project_dir, "subs.txt")
            if not os.path.exists(subs_file):
                log_warn(f"Subs file not found: {subs_file}")
                return
            target_file = subs_file
            log_info("Using all subs from subs.txt")
        else:  # latest (default)
            alive_file = os.path.join(project_dir, "alive.txt")
            if not os.path.exists(alive_file):
                log_warn(f"Alive file not found: {alive_file}")
                return
            target_file = alive_file
            log_info("Using latest alive targets from alive.txt")
        
        # Create eyewitness output directory
        eyewitness_dir = os.path.join(history_dir, "eyewitness")
        os.makedirs(eyewitness_dir, exist_ok=True)
        
        # Build eyewitness command
        cmd = [
            "eyewitness",
            "--web",
            "--prepend-https",
            "-f", target_file,
            "-d", eyewitness_dir
        ]
        
        # Add custom arguments if provided
        if hasattr(args, 'eyewitness_args') and args.eyewitness_args:
            custom_args = args.eyewitness_args.split()
            cmd.extend(custom_args)
            log_info(f"Using custom Eyewitness arguments: {args.eyewitness_args}")
        
        # Run eyewitness
        target_count = len(read_lines(target_file))
        log_info(f"Running Eyewitness on {target_count} targets")
        res = self.execute_command(cmd, timeout=1800)  # 30 minute timeout
        
        if res:
            # Create summary file with results info
            summary_path = os.path.join(history_dir, "screenshots_summary.txt")
            summary_lines = [
                f"Eyewitness completed successfully",
                f"Target file: {target_file}",
                f"Target count: {target_count}",
                f"Output directory: {eyewitness_dir}",
                f"Custom arguments: {getattr(args, 'eyewitness_args', None) or 'None'}",
                f"Target selection: {getattr(args, 'eyewitness_targets', 'latest')}"
            ]
            
            write_lines(summary_path, summary_lines)
            log_ok(f"Eyewitness screenshots completed - results in {eyewitness_dir}")


# Tool factory for easy access
class ToolFactory:
    """Factory class for creating tool instances"""
    
    _tools = {
        'subfinder': SubfinderTool,
        'httpx': HttpxTool,
        'naabu': NaabuTool,
        'nmap': NmapTool,
        'dirsearch': DirsearchTool,
        'gau_uro': GauUroTool,
        'secretfinder': SecretFinderTool,
        'nuclei': NucleiTool,
        'eyewitness': EyewitnessTool,
    }
    
    @classmethod
    def get_tool(cls, tool_name):
        """Get tool instance by name"""
        tool_class = cls._tools.get(tool_name)
        if tool_class:
            return tool_class()
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    @classmethod
    def list_tools(cls):
        """List all available tools"""
        return list(cls._tools.keys())