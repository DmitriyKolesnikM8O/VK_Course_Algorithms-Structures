import asyncio
import yaml
import os
import html
from datetime import datetime
from src.scanner import MasscanScanner
from src.analyzer import ServiceAnalyzer
from src.database import DatabaseManager
from src.notifier import TelegramNotifier
from src.vulnerability_scanner import NmapAnalyzer
from src.cve_checker import VulnersChecker
from src.exploit_linker import ExploitLinker
from src.asn_lookup import ASNResolver

async def main():
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] --- ЗАПУСК МОДУЛЯ СКАНИРОВАНИЯ ---")
    
    try:
        with open("config/config.yaml", "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] КРИТИЧЕСКАЯ ОШИБКА КОНФИГА: {e}"); return

    # 1. Подготовка БД
    db_path = config['database']['path']
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = DatabaseManager(db_path)
    await db.init_db()
    
    # 2. Обработка целей (IP + ASN)
    print("[*] Этап 1: Сбор и резолвинг целей...")
    raw_targets = str(config['scanner'].get('targets', '')).split(',')
    final_targets = []
    for t in raw_targets:
        t = t.strip()
        if not t: continue
        if t.upper().startswith("AS"):
            prefixes = await ASNResolver.get_prefixes(t)
            if prefixes:
                print(f"[+] ASN {t} развернут в: {', '.join(prefixes)}")
                final_targets.extend(prefixes)
            else:
                print(f"[!] Не удалось получить данные для {t}")
        else:
            final_targets.append(t)

    if not final_targets:
        print("[!] Список целей пуст. Выход."); return

    # 3. Инициализация инструментов
    scanner = MasscanScanner({**config['scanner'], 'targets': ",".join(final_targets)})
    analyzer = ServiceAnalyzer()
    nmap = NmapAnalyzer()
    notifier = TelegramNotifier(config['telegram']['token'], config['telegram']['chat_id'])
    v_checker = VulnersChecker(api_key=config.get('vulners', {}).get('api_key', ''))

    # 4. Быстрый скан Masscan
    print(f"[*] Этап 2: Запуск Masscan (целей: {len(final_targets)})...")
    known_ports = await db.get_all_known_ports()
    current_results = await scanner.run_scan()
    print(f"[+] Masscan завершен. Найдено открытых портов: {len(current_results)}")
    
    # 5. Глубокий анализ
    new_threats = []
    total_found = len(current_results)
    
    for idx, res in enumerate(current_results, 1):
        if (res.ip, res.port) not in known_ports:
            print(f"    [{idx}/{total_found}] АНАЛИЗ НОВОГО ПОРТА: {res.ip}:{res.port}")
            
            # Banner Grabbing
            print(f"      > Получение баннера...")
            res.banner = await analyzer.grab_banner(res.ip, res.port)
            
            # Nmap
            print(f"      > Запуск Nmap deep scan (может занять до 2 мин)...")
            s_name, s_version, _ = await nmap.analyze(res.ip, res.port)
            res.service = f"{s_name} {s_version}".strip()
            print(f"      > Сервис определен: {res.service}")
            
            # Vulners
            print(f"      > Поиск уязвимостей в Vulners API...")
            vuln_list = await v_checker.get_cves(s_name, s_version)
            enriched = ExploitLinker.wrap_cve_with_links(vuln_list)
            res.vulns = "\n\n".join(enriched) if enriched else "No critical CVEs found"
            
            # Telegram
            print(f"      > Отправка уведомления в Telegram...")
            safe_service = html.escape(res.service[:100])
            safe_banner = html.escape(res.banner[:200])
            msg = (f"🚨 <b>NEW THREAT DETECTED</b>\n"
                   f"Target: <code>{res.ip}:{res.port}</code>\n"
                   f"Service: <b>{safe_service}</b>\n"
                   f"Banner: <code>{safe_banner}</code>\n\n"
                   f"Vulns:\n{res.vulns}")
            
            resp = await notifier.send_message(msg)
            if resp and resp.status_code == 200:
                new_threats.append(res)
            else:
                print(f"      [!] Ошибка Telegram: {resp.text if resp else 'No response'}")
            
            await asyncio.sleep(0.5) 
        else:
            print(f"    [{idx}/{total_found}] Пропуск (уже в базе): {res.ip}:{res.port}")

    # 6. Сохранение в базу
    if new_threats:
        print(f"[*] Этап 3: Сохранение {len(new_threats)} новых записей в БД...")
        await db.update_ports(new_threats)
    
    total_db = len(await db.get_all_known_ports())
    summary = f"🏁 <b>Scan Complete</b>\nNew threats: {len(new_threats)}\nTotal in DB: {total_db}"
    await notifier.send_message(summary)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- СКАНИРОВАНИЕ ЗАВЕРШЕНО ---\n")

async def run_single_scan():
    await main()

if __name__ == "__main__":
    asyncio.run(run_single_scan())
