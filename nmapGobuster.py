import asyncio
import aiofiles
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional, Dict
import tempfile
import shutil
from pathlib import Path

@dataclass
class NmapResult:
    host: str
    open_ports: List[Dict]
    status: str
    error: Optional[str] = None

class AsyncNmapScanner:
    def __init__(self, max_concurrent_tasks: int = 3):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.temp_dir = tempfile.mkdtemp(prefix="nmap_scan_")
    
    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
    
    async def scan_host(self, host: str, ports: str = "1-1000", 
                       arguments: str = "-sS -T4", timeout: int = 600) -> NmapResult:
        # Реализация из предыдущего кода
        pass
    
    async def scan_multiple(self, hosts: List[str], **kwargs) -> Dict[str, NmapResult]:
        # Реализация из предыдущего кода
        pass