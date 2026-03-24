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
            "-oJ", "-", 
        ]
        
        print(f"[MASSCAN] Команда: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_chunks = []

        # Функция для чтения прогресса (stderr)
        async def read_stderr():
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                text = line.decode().strip()
                if "waiting" in text or "remaining" in text or "done" in text:
                    print(f"    [MASSCAN PROGRESS] {text}")

        # Функция для чтения результатов (stdout)
        async def read_stdout():
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                stdout_chunks.append(line.decode())

        # Запускаем чтение обоих потоков параллельно
        await asyncio.gather(read_stderr(), read_stdout())
        
        # Ждем завершения процесса
        await process.wait()

        raw_output = "".join(stdout_chunks).strip()
        if not raw_output:
            return []

        try:
            # Чистим мусор перед JSON (иногда masscan выводит текст в stdout)
            start_index = raw_output.find('[')
            if start_index != -1:
                data = json.loads(raw_output[start_index:])
                results = []
                for entry in data:
                    ip = entry['ip']
                    for p_info in entry['ports']:
                        results.append(PortResult(ip=ip, port=p_info['port'], protocol=p_info['proto']))
                return results
            return []
        except Exception as e:
            print(f"[!] Ошибка парсинга JSON: {e}")
            return []
