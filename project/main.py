import asyncio
import yaml
import os
from src.scanner import MasscanScanner
from src.analyzer import ServiceAnalyzer
from src.database import DatabaseManager
from src.notifier import TelegramNotifier
from src.vulnerability_scanner import NmapAnalyzer # Наш новый модуль

async def main():
    # 1. Загрузка конфигурации
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)

    # Убедимся, что папка для БД существует
    os.makedirs(os.path.dirname(config['database']['path']), exist_ok=True)

    # 2. Инициализация модулей
    db = DatabaseManager(config['database']['path'])
    await db.init_db()
    
    scanner = MasscanScanner(config['scanner'])
    quick_analyzer = ServiceAnalyzer()
    nmap_analyzer = NmapAnalyzer()
    notifier = TelegramNotifier(config['telegram']['token'], config['telegram']['chat_id'])

    print("[*] Starting Masscan recon...")
    
    # 3. Получаем список уже известных портов из БД
    known_ports = await db.get_all_known_ports()

    # 4. Запуск быстрого сканирования Masscan
    current_results = await scanner.run_scan()
    print(f"[*] Masscan found {len(current_results)} open ports.")

    new_threats = []

    # 5. Анализ найденных портов
    for res in current_results:
        # Проверяем, новый ли это порт
        if (res.ip, res.port) not in known_ports:
            print(f"[!] NEW PORT: {res.ip}:{res.port}. Starting deep analysis...")
            
            # А) Быстрый захват баннера
            res.banner = await quick_analyzer.grab_banner(res.ip, res.port)
            
            # Б) Глубокое сканирование Nmap + CVE (может занять 1-2 минуты)
            nmap_report = await nmap_analyzer.analyze(res.ip, res.port)
            
            # В) Отправка уведомления
            msg = (f"🚨 <b>NEW THREAT DETECTED</b>\n"
                   f"<b>Target:</b> <code>{res.ip}:{res.port}</code>\n"
                   f"<b>Banner:</b> <code>{res.banner}</code>\n\n"
                   f"<b>Nmap Report:</b>\n<pre>{nmap_report}</pre>")
            
            await notifier.send_message(msg)
            new_threats.append(res)
        else:
            print(f"[-] Port {res.ip}:{res.port} is already known. Skipping.")

    # 6. Сохраняем все найденные порты в базу как "известные" для следующего раза
    if current_results:
        await db.update_ports(current_results)
    
    if new_threats:
        print(f"[+] Done. Notified about {len(new_threats)} new threats.")
    else:
        print("[+] Done. No new threats found.")

if __name__ == "__main__":
    asyncio.run(main())
