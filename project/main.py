import asyncio
import yaml
import os
from src.scanner import MasscanScanner
from src.analyzer import ServiceAnalyzer
from src.database import DatabaseManager
from src.notifier import TelegramNotifier
from src.vulnerability_scanner import NmapAnalyzer
from src.cve_checker import VulnersChecker
from src.exploit_linker import ExploitLinker

async def main():
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)

    # Гарантируем создание папки data
    db_dir = os.path.dirname(config['database']['path'])
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    db = DatabaseManager(config['database']['path'])
    await db.init_db()
    
    scanner = MasscanScanner(config['scanner'])
    quick_analyzer = ServiceAnalyzer()
    nmap_analyzer = NmapAnalyzer()
    notifier = TelegramNotifier(config['telegram']['token'], config['telegram']['chat_id'])
    
    vulners_api_key = config.get('vulners', {}).get('api_key', '')
    v_checker = VulnersChecker(api_key=vulners_api_key)

    print("[*] Starting Masscan recon...")
    known_ports = await db.get_all_known_ports()

    current_results = await scanner.run_scan()
    print(f"[*] Masscan found {len(current_results)} open ports.")

    new_threats = []

    for res in current_results:
        if (res.ip, res.port) not in known_ports:
            print(f"[!] NEW PORT: {res.ip}:{res.port}. Starting deep analysis...")
            
            res.banner = await quick_analyzer.grab_banner(res.ip, res.port)
            service_name, version, nmap_report = await nmap_analyzer.analyze(res.ip, port=res.port)
            res.service = f"{service_name} {version}".strip() if version else service_name


                                    
            vuln_list = await v_checker.get_cves(service_name, version)

            enrichted_vulns = ExploitLinker.wrap_cve_with_links(vuln_list)

            vuln_str = "\n".join(enrichted_vulns) if enrichted_vulns else "No critical CVEs found"

            res.vulns = vuln_str
            
            # ВЫВОДИМ В КОНСОЛЬ ДЛЯ ПРОВЕРКИ
            print(f"[+] Vulners Result for {res.service}: {vuln_str}")
            
            msg = (f"🚨 <b>NEW THREAT DETECTED</b>\n"
                   f"<b>Target:</b> <code>{res.ip}:{res.port}</code>\n"
                   f"<b>Service:</b> <code>{res.service}</code>\n"
                   f"<b>Vulners API Info:</b>\n{vuln_str}\n\n"
                   f"<b>Nmap Report:</b>\n<pre>{nmap_report}</pre>")
            
            await notifier.send_message(msg)
            new_threats.append(res)
        else:
            print(f"[-] Port {res.ip}:{res.port} is already known. Skipping.")

    if new_threats:
        await db.update_ports(new_threats)
    
    total_in_db = len(await db.get_all_known_ports())
    summary_msg = (f"🏁 <b>Сканирование завершено</b>\nОбъект: {config['scanner']['targets']}\nВсего в базе: {total_in_db}")
    await notifier.send_message(summary_msg)

async def run_single_scan():
    await main()

if __name__ == "__main__":
    asyncio.run(run_single_scan())
