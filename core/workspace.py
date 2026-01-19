import os
from datetime import datetime

def create_workspace():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("workspaces", timestamp)
    os.makedirs(path, exist_ok=True)
    return path

