import os
import shutil
import subprocess
import time

from core.logger import log_info, log_debug, log_warn, get_verbose_level
from core.rate_limiter import get_global_rate_limiter
from core.tool_installer import ToolInstaller


def command_exists(command_name):
    return shutil.which(command_name) is not None


def command_exists_with_installer(command_name):
    """Check if command exists, using the tool installer for more detailed checks."""
    # First try the basic check
    if shutil.which(command_name):
        return True
    
    # Then use the installer for more detailed detection
    installer = ToolInstaller()
    return installer.check_tool_installed(command_name)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def run_command(cmd_list, cwd=None, timeout=None, apply_rate_limit=False):
    if get_verbose_level() >= 1:
        cwd_part = f" (cwd={cwd})" if cwd else ""
        log_info(f"run: {' '.join(cmd_list)}{cwd_part}")

    # Apply rate limiting if requested
    if apply_rate_limit:
        rate_limiter = get_global_rate_limiter()
        tool_name = cmd_list[0] if cmd_list else None
        wait_time = rate_limiter.acquire(tool_name)
        if wait_time > 0:
            time.sleep(wait_time)

    try:
        res = subprocess.run(
            cmd_list,
            cwd=cwd,
            timeout=timeout,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        log_warn(f"missing tool: {cmd_list[0]} ({e})")
        return _make_result(127, "", str(e))
    except subprocess.TimeoutExpired as e:
        log_warn(f"timeout: {' '.join(cmd_list)}")
        stdout = e.stdout or ""
        stderr = str(e)
        return _make_result(124, stdout, stderr)

    if get_verbose_level() >= 1 and res.stderr:
        log_info(f"stderr: {res.stderr.strip()[:2000]}")

    if get_verbose_level() >= 2 and res.stdout:
        log_debug(f"stdout: {res.stdout.strip()[:2000]}")

    return res


def _make_result(returncode, stdout, stderr):
    class result:
        pass
    r = result()
    r.returncode = returncode
    r.stdout = stdout or ""
    r.stderr = stderr or ""
    return r

