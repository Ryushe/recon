import os
import time
from datetime import datetime

_verbose_level = 0
_log_file_handle = None


def init_logger(project_dir, module_name="recon"):
    global _log_file_handle

    logs_dir = os.path.join(project_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = os.path.join(logs_dir, f"{module_name}_{ts}.log")

    _log_file_handle = open(log_path, "a", encoding="utf-8")
    log_info(f"log_file: {log_path}")


def close_logger():
    global _log_file_handle
    if _log_file_handle:
        _log_file_handle.close()
        _log_file_handle = None


def set_verbose_level(level):
    global _verbose_level
    _verbose_level = int(level or 0)


def get_verbose_level():
    return _verbose_level


def _write(msg):
    if _log_file_handle:
        _log_file_handle.write(msg + "\n")
        _log_file_handle.flush()


def log_info(msg):
    if _verbose_level >= 1:
        print(f"[i] {msg}")
    _write(f"[INFO] {msg}")


def log_debug(msg):
    if _verbose_level >= 2:
        print(f"[d] {msg}")
    _write(f"[DEBUG] {msg}")


def log_warn(msg):
    print(f"[!] {msg}")
    _write(f"[WARN] {msg}")


def log_ok(msg):
    print(f"[+] {msg}")
    _write(f"[OK] {msg}")


def time_block(label):
    start = time.time()
    log_debug(f"{label}: start")

    def done():
        elapsed = time.time() - start
        log_debug(f"{label}: end ({elapsed:.2f}s)")

    return done

