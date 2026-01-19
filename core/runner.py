import os
import shutil
import subprocess

from core.logger import log_info, log_debug, log_warn, get_verbose_level


def command_exists(command_name):
    return shutil.which(command_name) is not None


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def run_command(cmd_list, cwd=None, timeout=None):
    if get_verbose_level() >= 1:
        cwd_part = f" (cwd={cwd})" if cwd else ""
        log_info(f"run: {' '.join(cmd_list)}{cwd_part}")

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

