import os
import sys
import subprocess
import shutil
import platform
import urllib.request
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.logger import log_info, log_ok, log_warn, log_debug
from core.config import load_config


class ToolInstaller:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or load_config() or {}
        self.install_config = self.config.get('install_urls', {})
        self.install_settings = self.config.get('installation', {})
        self.system = platform.system().lower()
        self.default_install_dir = os.path.expanduser(self.install_settings.get('default_install_dir', '~/tools'))
        self.go_bin_dir = os.path.expanduser(self.install_settings.get('go_bin_dir', '~/.local/bin'))
        
    def check_go_available(self) -> bool:
        """Check if Go is available for Go-based tools."""
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is already installed."""
        tool_config = self.install_config.get(tool_name, {})
        if not tool_config:
            return False
        
        tool_type = tool_config.get('type', '')
        
        if tool_type == 'go':
            binary_path = os.path.expanduser(tool_config.get('binary_path', ''))
            if binary_path and os.path.exists(binary_path):
                return True
            # Also check in PATH
            return shutil.which(tool_name) is not None
            
        elif tool_type == 'git':
            install_path = os.path.expanduser(tool_config.get('install_path', ''))
            if install_path and os.path.exists(install_path):
                return True
            python_package = tool_config.get('python_package', '')
            if python_package:
                # Try multiple pip commands
                for pip_cmd in ['pip3', 'pip', 'python3 -m pip', 'python -m pip']:
                    try:
                        if 'python' in pip_cmd:
                            cmd = pip_cmd.split()
                        else:
                            cmd = [pip_cmd]
                        cmd.extend(['show', python_package])
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            return True
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                return False
                    
        elif tool_type == 'system':
            binary_path = tool_config.get('binary_path', '')
            if binary_path and os.path.exists(binary_path):
                return True
            return shutil.which(tool_name) is not None
            
        return False
    
    def install_go_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install a Go-based tool."""
        if not self.check_go_available():
            log_warn(f"Go is not available. Cannot install {tool_name}.")
            log_info("Please install Go first: https://golang.org/dl/")
            return False
        
        repository = tool_config.get('repository', '')
        binary_path = os.path.expanduser(tool_config.get('binary_path', ''))
        version = tool_config.get('version', 'latest')
        
        if not repository:
            log_warn(f"No repository specified for {tool_name}")
            return False
        
        # Ensure GOBIN directory exists
        os.makedirs(os.path.dirname(binary_path), exist_ok=True)
        
        try:
            # Set GOBIN environment variable
            env = os.environ.copy()
            env['GOBIN'] = os.path.dirname(binary_path)
            
            if version == 'latest':
                cmd = ['go', 'install', f'{repository}@latest']
            else:
                cmd = ['go', 'install', f'{repository}@{version}']
            
            log_info(f"Installing {tool_name} with: {' '.join(cmd)}")
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                log_ok(f"Successfully installed {tool_name}")
                return True
            else:
                log_warn(f"Failed to install {tool_name}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            log_warn(f"Installation of {tool_name} timed out")
            return False
        except Exception as e:
            log_warn(f"Error installing {tool_name}: {e}")
            return False
    
    def install_git_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install a Git-based tool."""
        repository = tool_config.get('repository', '')
        install_path = os.path.expanduser(tool_config.get('install_path', ''))
        python_package = tool_config.get('python_package', '')
        install_command = tool_config.get('install_command', '')
        
        if repository:
            # Clone the repository
            os.makedirs(os.path.dirname(install_path), exist_ok=True)
            
            if os.path.exists(install_path):
                log_info(f"Updating {tool_name} repository...")
                cmd = ['git', '-C', install_path, 'pull']
            else:
                log_info(f"Cloning {tool_name} repository...")
                cmd = ['git', 'clone', f'https://github.com/{repository}.git', install_path]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    log_warn(f"Failed to clone/update {tool_name}: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                log_warn(f"Git operation for {tool_name} timed out")
                return False
        
        # Install Python package if specified
        if install_command:
            log_info(f"Running install command for {tool_name}: {install_command}")
            try:
                result = subprocess.run(install_command, shell=True, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    log_ok(f"Successfully installed {tool_name}")
                    return True
                else:
                    # Try alternative pip commands if the first one fails
                    if 'pip3' in install_command and 'not found' in result.stderr:
                        log_info(f"pip3 not found, trying alternative pip commands...")
                        alternatives = ['pip install dirsearch', 'python3 -m pip install dirsearch', 'python -m pip install dirsearch']
                        for alt_cmd in alternatives:
                            log_info(f"Trying: {alt_cmd}")
                            result = subprocess.run(alt_cmd, shell=True, capture_output=True, text=True, timeout=300)
                            if result.returncode == 0:
                                log_ok(f"Successfully installed {tool_name} with alternative command")
                                return True
                    
                    log_warn(f"Failed to install {tool_name}: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                log_warn(f"Installation of {tool_name} timed out")
                return False
        
        return False
    
    def install_system_tool(self, tool_name: str, tool_config: Dict) -> bool:
        """Install a system package."""
        package_manager = tool_config.get('package_manager', {})
        
        # Determine the appropriate package manager command
        if self.system == 'linux':
            # Try to detect the Linux distribution
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read().lower()
                if 'ubuntu' in os_release or 'debian' in os_release:
                    cmd = package_manager.get('ubuntu', package_manager.get('debian', ''))
                elif 'fedora' in os_release:
                    cmd = package_manager.get('fedora', '')
                elif 'centos' in os_release or 'rhel' in os_release:
                    cmd = package_manager.get('centos', '')
                elif 'arch' in os_release:
                    cmd = package_manager.get('arch', '')
                else:
                    log_warn(f"Unsupported Linux distribution for {tool_name}")
                    return False
            except FileNotFoundError:
                log_warn(f"Could not determine Linux distribution for {tool_name}")
                return False
        elif self.system == 'darwin':
            cmd = package_manager.get('macos', '')
        else:
            log_warn(f"Unsupported operating system for {tool_name}: {self.system}")
            return False
        
        if not cmd:
            log_warn(f"No package manager command specified for {tool_name} on {self.system}")
            return False
        
        log_info(f"Installing {tool_name} with: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                log_ok(f"Successfully installed {tool_name}")
                return True
            else:
                log_warn(f"Failed to install {tool_name}: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            log_warn(f"Installation of {tool_name} timed out")
            return False
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a specific tool."""
        tool_config = self.install_config.get(tool_name, {})
        if not tool_config:
            log_warn(f"No installation configuration found for {tool_name}")
            return False
        
        # Check if already installed
        if self.check_tool_installed(tool_name):
            log_info(f"{tool_name} is already installed")
            return True
        
        tool_type = tool_config.get('type', '')
        log_info(f"Installing {tool_name} (type: {tool_type})")
        
        if tool_type == 'go':
            return self.install_go_tool(tool_name, tool_config)
        elif tool_type == 'git':
            return self.install_git_tool(tool_name, tool_config)
        elif tool_type == 'system':
            return self.install_system_tool(tool_name, tool_config)
        else:
            log_warn(f"Unknown tool type for {tool_name}: {tool_type}")
            return False
    
    def install_all_tools(self) -> Dict[str, bool]:
        """Install all configured tools."""
        results = {}
        
        log_info("Starting installation of all tools...")
        
        # Check prerequisites
        if not self.check_go_available():
            log_warn("Go is not available. Go-based tools will be skipped.")
        
        for tool_name in self.install_config.keys():
            results[tool_name] = self.install_tool(tool_name)
        
        return results
    
    def list_tools_status(self) -> Dict[str, Dict]:
        """List the installation status of all tools."""
        status = {}
        
        for tool_name, tool_config in self.install_config.items():
            installed = self.check_tool_installed(tool_name)
            tool_type = tool_config.get('type', '')
            status[tool_name] = {
                'installed': installed,
                'type': tool_type,
                'config': tool_config
            }
        
        return status
    
    def get_missing_tools(self) -> List[str]:
        """Get list of tools that are not installed."""
        missing = []
        for tool_name in self.install_config.keys():
            if not self.check_tool_installed(tool_name):
                missing.append(tool_name)
        return missing


def install_tools_interactive() -> None:
    """Interactive tool installation."""
    installer = ToolInstaller()
    
    log_info("Checking tool installation status...")
    status = installer.list_tools_status()
    
    installed_count = sum(1 for s in status.values() if s['installed'])
    total_count = len(status)
    
    log_info(f"Found {installed_count}/{total_count} tools installed")
    
    for tool_name, info in status.items():
        status_str = "✓" if info['installed'] else "✗"
        log_info(f"  {status_str} {tool_name} ({info['type']})")
    
    missing = installer.get_missing_tools()
    if missing:
        log_info(f"\nMissing tools: {', '.join(missing)}")
        
        response = input("\nDo you want to install missing tools? (y/n): ").lower().strip()
        if response in ['y', 'yes']:
            results = installer.install_all_tools()
            
            success_count = sum(1 for r in results.values() if r)
            log_info(f"\nInstallation complete: {success_count}/{len(results)} tools installed successfully")
            
            for tool_name, success in results.items():
                status_str = "✓" if success else "✗"
                log_info(f"  {status_str} {tool_name}")


def check_and_install_prerequisites() -> bool:
    """Check and suggest installation of prerequisites."""
    installer = ToolInstaller()
    install_settings = installer.install_settings
    prerequisites = install_settings.get('prerequisites', {})
    
    system = installer.system
    
    if system == 'linux':
        # Try to detect the Linux distribution
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read().lower()
            if 'ubuntu' in os_release or 'debian' in os_release:
                cmd = prerequisites.get('ubuntu_debian', '')
            elif 'fedora' in os_release or 'centos' in os_release or 'rhel' in os_release:
                cmd = prerequisites.get('fedora_centos', '')
            elif 'arch' in os_release:
                cmd = prerequisites.get('arch', '')
            else:
                log_warn(f"Unsupported Linux distribution. Please install git, golang, python3-pip, libpcap-dev manually")
                return False
        except FileNotFoundError:
            log_warn(f"Could not determine Linux distribution. Please install git, golang, python3-pip, libpcap-dev manually")
            return False
    elif system == 'darwin':
        cmd = prerequisites.get('macos', '')
    else:
        log_warn(f"Unsupported operating system: {system}")
        return False
    
    if cmd:
        log_info("Installing prerequisites...")
        log_info(f"Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                log_ok("Prerequisites installed successfully!")
                return True
            else:
                log_warn(f"Failed to install prerequisites: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            log_warn("Prerequisite installation timed out")
            return False
    
    return False


def install_tools_all() -> None:
    """Install all configured tools."""
    log_info("Checking prerequisites...")
    if not check_and_install_prerequisites():
        log_warn("Prerequisites installation failed. Some tools may not install correctly.")
    
    installer = ToolInstaller()
    results = installer.install_all_tools()
    
    success_count = sum(1 for r in results.values() if r)
    total_count = len(results)
    
    log_info(f"Installation complete: {success_count}/{total_count} tools installed successfully")
    
    for tool_name, success in results.items():
        status_str = "✓" if success else "✗"
        log_info(f"  {status_str} {tool_name}")
    
    if success_count == total_count:
        log_ok("All tools installed successfully!")
    else:
        log_warn(f"Some tools failed to install. Check the logs above for details.")