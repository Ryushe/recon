import time
import threading
from typing import Dict, Optional
from core.logger import log_debug, log_warn


class GlobalRateLimiter:
    def __init__(self, requests_per_second: float = 10, burst_capacity: int = 50):
        self.rps = requests_per_second
        self.burst_capacity = burst_capacity
        self.tokens = burst_capacity
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.tool_limits: Dict[str, float] = {}
        self.enabled = True
        
    def acquire(self, tool_name: Optional[str] = None, tokens: int = 1) -> float:
        if not self.enabled:
            return 0.0
            
        with self.lock:
            current_time = time.time()
            time_elapsed = current_time - self.last_update
            
            # Add tokens based on time elapsed
            self.tokens += time_elapsed * self.rps
            if self.tokens > self.burst_capacity:
                self.tokens = self.burst_capacity
            
            # Check tool-specific limits
            effective_rps = self.tool_limits.get(tool_name, self.rps) if tool_name else self.rps
            
            # Calculate wait time if needed
            if self.tokens < tokens:
                wait_time = (tokens - self.tokens) / effective_rps
                self.last_update = current_time + wait_time
                self.tokens = 0
                log_debug(f"Rate limiting: waiting {wait_time:.2f}s for {tool_name}")
                return wait_time
            else:
                self.tokens -= tokens
                self.last_update = current_time
                return 0.0
    
    def set_tool_limit(self, tool_name: str, requests_per_second: float):
        with self.lock:
            self.tool_limits[tool_name] = requests_per_second
            log_debug(f"Set rate limit for {tool_name}: {requests_per_second} RPS")
    
    def set_global_rate(self, requests_per_second: float):
        with self.lock:
            self.rps = requests_per_second
            log_debug(f"Set global rate limit: {requests_per_second} RPS")
    
    def disable(self):
        self.enabled = False
        log_debug("Rate limiting disabled")
    
    def enable(self):
        self.enabled = True
        log_debug("Rate limiting enabled")
    
    def get_status(self) -> Dict:
        with self.lock:
            return {
                'enabled': self.enabled,
                'global_rps': self.rps,
                'burst_capacity': self.burst_capacity,
                'current_tokens': self.tokens,
                'tool_limits': self.tool_limits.copy()
            }


# Global instance
_global_rate_limiter: Optional[GlobalRateLimiter] = None
_rate_limiter_lock = threading.Lock()


def get_global_rate_limiter(requests_per_second: float = 10, burst_capacity: int = 50) -> GlobalRateLimiter:
    global _global_rate_limiter
    with _rate_limiter_lock:
        if _global_rate_limiter is None:
            _global_rate_limiter = GlobalRateLimiter(requests_per_second, burst_capacity)
        return _global_rate_limiter


def configure_rate_limiter(config: Dict):
    limiter = get_global_rate_limiter()
    
    rate_config = config.get('rate_limiting', {})
    if rate_config:
        global_rps = rate_config.get('global_rps', 10)
        burst_capacity = rate_config.get('burst_capacity', 50)
        
        limiter.set_global_rate(global_rps)
        limiter.burst_capacity = burst_capacity
        
        # Set tool-specific limits
        tool_limits = rate_config.get('tool_limits', {})
        for tool, rps in tool_limits.items():
            limiter.set_tool_limit(tool, rps)
    
    # Check if rate limiting should be disabled
    if config.get('disable_rate_limiting', False):
        limiter.disable()