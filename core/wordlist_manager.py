import os
from typing import List, Optional
from core.logger import log_info, log_warn, log_debug
from core.config import load_config


class WordlistManager:
    def __init__(self, config: dict = None):
        self.config = config or load_config()
        self.wordlist_config = self.config.get('wordlists', {})
        
    def get_wordlist(self, list_type: str = 'default', custom_path: str = None) -> str:
        # Custom path takes highest priority
        if custom_path and os.path.exists(custom_path):
            log_info(f"Using custom wordlist: {custom_path}")
            return custom_path
        
        # Check predefined sizes
        if list_type in ['small', 'medium', 'large']:
            predefined = self.wordlist_config.get('predefined_sizes', {})
            if list_type in predefined:
                wordlist_path = predefined[list_type]
                if os.path.exists(wordlist_path):
                    log_info(f"Using {list_type} wordlist: {wordlist_path}")
                    return wordlist_path
                else:
                    log_warn(f"Predefined {list_type} wordlist not found: {wordlist_path}")
        
        # Check custom directories
        custom_dirs = self.wordlist_config.get('custom_directories', [])
        for directory in custom_dirs:
            expanded_dir = os.path.expanduser(directory)
            if os.path.exists(expanded_dir):
                potential_wordlist = os.path.join(expanded_dir, f"{list_type}.txt")
                if os.path.exists(potential_wordlist):
                    log_info(f"Found wordlist in custom directory: {potential_wordlist}")
                    return potential_wordlist
        
        # Fallback to default
        default_path = self.wordlist_config.get('default_dirsearch')
        if default_path and os.path.exists(default_path):
            log_info(f"Using default wordlist: {default_path}")
            return default_path
        
        raise FileNotFoundError(f"No wordlist found for type: {list_type}")
    
    def validate_wordlist(self, wordlist_path: str) -> bool:
        if not os.path.exists(wordlist_path):
            log_warn(f"Wordlist does not exist: {wordlist_path}")
            return False
        
        # Check file size
        try:
            file_size = os.path.getsize(wordlist_path)
            validation_config = self.wordlist_config.get('validation', {})
            min_size = validation_config.get('min_size', 10)
            max_size = validation_config.get('max_size', 1000000)
            
            if file_size < min_size:
                log_warn(f"Wordlist too small: {file_size} bytes (min: {min_size})")
                return False
            
            if file_size > max_size:
                log_warn(f"Wordlist too large: {file_size} bytes (max: {max_size})")
                return False
            
            log_debug(f"Wordlist validation passed: {wordlist_path} ({file_size} bytes)")
            return True
            
        except OSError as e:
            log_warn(f"Error validating wordlist: {e}")
            return False
    
    def list_available_wordlists(self) -> List[str]:
        available = []
        
        # Check predefined sizes
        predefined = self.wordlist_config.get('predefined_sizes', {})
        for name, path in predefined.items():
            if os.path.exists(path):
                available.append(f"{name}: {path}")
        
        # Check custom directories
        custom_dirs = self.wordlist_config.get('custom_directories', [])
        for directory in custom_dirs:
            expanded_dir = os.path.expanduser(directory)
            if os.path.exists(expanded_dir):
                for filename in os.listdir(expanded_dir):
                    if filename.endswith('.txt'):
                        full_path = os.path.join(expanded_dir, filename)
                        available.append(f"custom: {full_path}")
        
        # Check default
        default_path = self.wordlist_config.get('default_dirsearch')
        if default_path and os.path.exists(default_path):
            available.append(f"default: {default_path}")
        
        return available