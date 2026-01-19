import os
import shutil
import subprocess


def command_exists(command_name):
    return shutil.which(command_name) is not None


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def run_command(cmd_list, cwd=None, timeout=None):
    return subprocess.run(
        cmd_list,
        cwd=cwd,
        timeout=timeout,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

