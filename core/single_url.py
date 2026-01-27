import os
import tempfile
import shutil
from core.project import ensure_project, append_lines
from core.logger import log_info, log_ok, log_warn


def setup_single_url_mode(url, args, config):
    """
    Set up single URL mode by creating a temp directory and setting up the project structure.
    
    Args:
        url: The target URL to process
        args: Command line arguments
        config: Configuration object
        
    Returns:
        tuple: (project_dir, updated_args) - the temporary project directory and potentially modified args
    """
    # Create temporary directory in /tmp
    temp_dir = tempfile.mkdtemp(prefix="recon_single_url_")
    log_info(f"Created temporary directory: {temp_dir}")
    
    # Ensure project structure
    project_dir = ensure_project(temp_dir)
    
    # Create URLs.txt file and append the URL
    urls_file = os.path.join(project_dir, "urls.txt")
    append_lines(urls_file, [url])
    log_ok(f"Added URL to {urls_file}")
    
    # Create wild.txt file and append the URL
    wild_file = os.path.join(project_dir, "wild.txt")
    append_lines(wild_file, [url])
    log_ok(f"Added URL to {wild_file}")
    
    # Update args to use the temporary project directory
    args.project = project_dir
    args.url = None  # Clear the URL flag to avoid conflicts
    
    return project_dir


def cleanup_temp_directory(temp_dir):
    """
    Clean up the temporary directory after use.
    
    Args:
        temp_dir: Path to the temporary directory to remove
    """
    try:
        shutil.rmtree(temp_dir)
        log_info(f"Cleaned up temporary directory: {temp_dir}")
    except Exception as e:
        log_warn(f"Failed to clean up temporary directory {temp_dir}: {e}")