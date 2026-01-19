import time

_verbose_level = 0

def set_verbose_level(level):
    global _verbose_level
    _verbose_level = int(level or 0)

def get_verbose_level():
    return _verbose_level

def log_info(msg):
    if _verbose_level >= 1:
        print(f"[i] {msg}")

def log_debug(msg):
    if _verbose_level >= 2:
        print(f"[d] {msg}")

def log_warn(msg):
    print(f"[!] {msg}")

def log_ok(msg):
    print(f"[+] {msg}")

def time_block(label):
    start = time.time()
    def done():
        elapsed = time.time() - start
        if _verbose_level >= 2:
            print(f"[d] {label} took {elapsed:.2f}s")
    return done

