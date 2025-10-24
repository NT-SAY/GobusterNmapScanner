import asyncio
from Gobuster import AsyncGobuster, GobusterResult
from nmapGobuster import AsyncNmapScanner, NmapResult

class AdvancedScanner:
    """Оптимизированный комбинированный сканер"""
    def __init__(self):
        self.nmap_scanner = AsyncNmapScanner(max_concurrent_tasks=3)
        self.gobuster_scanner = AsyncGobuster(max_concurrent_tasks=8)
        self.http_keywords = {'http', 'https', 'www', 'apache', 'nginx', 'iis', 'tomcat', 'jetty'}
    
    async def full_scan(self, target: str):
        """Оптимизированное полное сканирование"""
        print(f"[+] Запускаем быстрое nmap сканирование для {target}")
        
        # Быстрое сканирование общих портов
        nmap_results = await self.nmap_scanner.scan_host(
            target, 
            ports="80,443,8080,8443,8000,8008,8888,3000,5000,9000",
            arguments="-sS -T4 --min-rate 2000 --max-retries 1",
            timeout=120
        )
        
        if nmap_results.status != "success":
            print(f"[-] Ошибка nmap: {nmap_results.error}")
            return
        
        print(f"[+] Найдено открытых портов: {len(nmap_results.open_ports)}")
        
        # Быстрая фильтрация HTTP сервисов
        http_services = []
        for port in nmap_results.open_ports:
            service_lower = port['service'].lower()
            product_lower = port['product'].lower()
            
            if (any(kw in service_lower for kw in self.http_keywords) or
                any(kw in product_lower for kw in self.http_keywords) or
                port['port'] in ['80', '443', '8080', '8443']):
                
                protocol = "https" if port['port'] == "443" or "ssl" in product_lower else "http"
                url = f"{protocol}://{target}:{port['port']}"
                http_services.append({
                    'url': url,
                    'port': port['port'],
                    'service': port['service']
                })
        
        if not http_services:
            print("[-] HTTP not found")
            return
        
        print(f"[+] Found HTTP: {len(http_services)}")
        
        # Параллельное сканирование Gobuster с приоритетами
        print("\n[+] Gobuster scan...")
        
        # Приоритизация: сначала стандартные порты
        http_services.sort(key=lambda x: (x['port'] not in ['80', '443'], x['port']))
        
        urls = [service['url'] for service in http_services]
        gobuster_results = await self.gobuster_scanner.scan_multiple(
            urls,
            wordlist="/usr/share/wordlists/dirb/common.txt",
            threads=150,  
            timeout=180   
        )
        
        # Быстрый вывод результатов
        print("\n[+] resoult Gobuster:")
        successful_scans = 0
        for url, result in gobuster_results.items():
            if result.status == "success" and result.found_paths:
                print(f"✅ {url}: {len(result.found_paths)} ways")
                successful_scans += 1
                if len(result.found_paths) > 0:
                    print(f"   → {result.found_paths[0]}" + 
                         (f". . .and more {len(result.found_paths)-1}" if len(result.found_paths) > 1 else ""))
            elif result.status == "success":
                print(f"ℹ️  {url}: ways not found")
            else:
                print(f"❌ {url}: error")
        
        print(f"\n[+] scan is over: {successful_scans}/{len(http_services)} scans is good")

async def main():
    scanner = AdvancedScanner()
    
    target = input("enter (IP or domen): ").strip()
    if not target:
        target = "example.com"
    
    start_time = asyncio.get_event_loop().time()
    await scanner.full_scan(target)
    end_time = asyncio.get_event_loop().time()
    
    print(f"\n⏱️ time of ready: {end_time - start_time:.2f} second")

if __name__ == "__main__":
    asyncio.run(main())