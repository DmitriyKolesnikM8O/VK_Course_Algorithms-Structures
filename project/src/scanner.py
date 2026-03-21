import asyncio
import json
import subprocess
from src.models import PortResult

class MasscanScanner:
    def __init__(self, config):
        self.cfg = config

    async def run_scan(self):
        cmd = [
            "sudo", "masscan",
            self.cfg['targets'],
            "-p", self.cfg['ports'],
            "--max-rate", str(self.cfg['rate']),
            "-e", self.cfg['interface'],
            "-oJ", "-"  # Вывод JSON в stdout
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        # Мы игнорируем stderr, так как Masscan пишет туда служебную инфу
        if not stdout:
            return []

        try:
            # Декодируем и чистим вывод (иногда Masscan добавляет мусор)
            raw_output = stdout.decode().strip()
            if not raw_output or raw_output == "[]":
                return []
                
            data = json.loads(raw_output)
            results = []
            for entry in data:
                ip = entry['ip']
                for p_info in entry['ports']:
                    results.append(PortResult(
                        ip=ip, 
                        port=p_info['port'], 
                        protocol=p_info['proto']
                    ))
            return results
        except Exception as e:
            print(f"[!] Ошибка парсинга JSON: {e}")
            return []
