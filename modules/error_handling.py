import asyncio
import logging
from typing import Callable, Any, Optional
from functools import wraps
import time
import traceback

class AdvancedErrorHandler:
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.logger = self._setup_logger()
        self.total_requests = 0
        self.failed_requests = 0
        self.retried_requests = 0
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('ErrorHandler')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _calculate_delay(self, attempt: int) -> float:
        return min(self.base_delay * (2 ** attempt), 60.0)
    
    async def execute_async(self, func: Callable, *args, **kwargs) -> Any:
        self.total_requests += 1
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except asyncio.TimeoutError:
                last_exception = Exception(f"Timeout on attempt {attempt + 1}")
                self.logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries + 1}")
            except Exception as e:
                last_exception = e
                self.logger.error(f"Error on attempt {attempt + 1}/{self.max_retries + 1}: {str(e)}")
            
            if attempt < self.max_retries:
                self.retried_requests += 1
                delay = self._calculate_delay(attempt)
                self.logger.info(f"Retrying in {delay:.2f}s...")
                await asyncio.sleep(delay)
        
        self.failed_requests += 1
        if last_exception:
            raise last_exception
        raise Exception("Request failed after all retries")
    
    def get_statistics(self):
        return {
            'total_requests': self.total_requests,
            'failed_requests': self.failed_requests,
            'retried_requests': self.retried_requests
        }

def with_error_handling(max_retries: int = 3):
    def decorator(func: Callable):
        handler = AdvancedErrorHandler(max_retries=max_retries)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await handler.execute_async(func, *args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler.logger.error(f"Error: {str(e)}")
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

def handle_error(error: Exception):

    logger = logging.getLogger('ErrorHandler')
    logger.setLevel(logging.ERROR)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    logger.error(f"Fatal Error: {str(error)}")
    logger.error(traceback.format_exc())
    print(f"\n❌ Error: {str(error)}")
    print("Check the logs for more details.")