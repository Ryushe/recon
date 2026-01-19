import os
from datetime import date


def ensure_project(project_dir):
    project_dir = os.path.abspath(project_dir)
    os.makedirs(project_dir, exist_ok=True)
    history_dir = os.path.join(project_dir, "history")
    os.makedirs(history_dir, exist_ok=True)
    return project_dir


def today_history_dir(project_dir):
    day = date.today().isoformat()
    path = os.path.join(project_dir, "history", day)
    os.makedirs(path, exist_ok=True)
    return path


def canonical_path(project_dir, file_name):
    return os.path.join(project_dir, file_name)


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f]


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            if line is None:
                continue
            s = str(line).strip()
            if not s:
                continue
            f.write(s + "\n")


def append_lines(path, lines):
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            if line is None:
                continue
            s = str(line).strip()
            if not s:
                continue
            f.write(s + "\n")


def compute_new_lines(existing_lines, candidate_lines):
    existing_set = set([x.strip() for x in existing_lines if x and x.strip()])
    new_lines = []
    for line in candidate_lines:
        if not line:
            continue
        s = line.strip()
        if not s:
            continue
        if s not in existing_set:
            existing_set.add(s)
            new_lines.append(s)
    return new_lines


def merge_into_canonical(project_dir, canonical_file, candidate_lines, history_dir, delta_file_name):
    canonical_file_path = canonical_path(project_dir, canonical_file)
    existing = read_lines(canonical_file_path)
    new_lines = compute_new_lines(existing, candidate_lines)

    delta_path = os.path.join(history_dir, delta_file_name)
    write_lines(delta_path, new_lines)

    if new_lines:
        append_lines(canonical_file_path, new_lines)

    return {
        "canonical_path": canonical_file_path,
        "delta_path": delta_path,
        "new_count": len(new_lines),
    }

