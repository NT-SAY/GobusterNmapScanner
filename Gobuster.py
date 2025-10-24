import asyncio
import json
from dataclasses import dataclass
from typing import List, Optional, Dict

@dataclass
class GobusterResult:
    url: str
    found_paths: List[str]
    status: str
    error: Optional[str] = None

class AsyncGobuster:
    def __init__(self, max_concurrent_tasks: int = 5):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
    
    async def run_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                      extensions: str = "php,txt,html,js", threads: int = 100, 
                      timeout: int = 300) -> GobusterResult:
        # Реализация из предыдущего кода
        pass
    
    async def scan_multiple(self, urls: List[str], **kwargs) -> Dict[str, GobusterResult]:
        # Реализация из предыдущего кода
        pass