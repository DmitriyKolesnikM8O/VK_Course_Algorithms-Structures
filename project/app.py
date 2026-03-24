import asyncio
import traceback
import yaml
import uvicorn
import aiosqlite
import os
import json
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Импорт логики и менеджера БД
from main import run_single_scan
from src.database import DatabaseManager

SCAN_STATUS = "idle"
NEXT_SCAN_TIME = None

def load_config():
    """Загрузка конфигурации с защитой от отсутствующих ключей."""
    path = "config/config.yaml"
    defaults = {
        "scanner": {"targets": "8.8.8.8", "ports": "80, 443", "rate": 1000, "interface": "eth0"},
        "telegram": {"token": "", "chat_id": ""},
        "vulners": {"api_key": ""},
        "database": {"path": "data/scan_results.db"},
        "scheduling": {"enabled": False, "interval_minutes": 60}
    }
    
    if not os.path.exists(path):
        return defaults

    with open(path, "r") as f:
        try:
            config = yaml.safe_load(f) or {}
        except:
            config = {}
    
    # Рекурсивное слияние с дефолтами
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for sk, sv in value.items():
                if sk not in config[key]:
                    config[key][sk] = sv
    return config

def save_config(config):
    """Сохранение конфигурации в YAML."""
    os.makedirs("config", exist_ok=True)
    with open("config/config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

async def background_scan_task():
    """Фоновая задача сканирования."""
    global SCAN_STATUS
    if SCAN_STATUS == "scanning": return
    SCAN_STATUS = "scanning"
    print(f"[PROCESS] Сканирование начато: {datetime.now().strftime('%H:%M:%S')}")
    try:
        await run_single_scan()
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        traceback.print_exc()
    finally:
        SCAN_STATUS = "idle"
        print(f"[PROCESS] Сканирование завершено.")

async def periodic_scan_loop():
    """Фоновый цикл планировщика."""
    global NEXT_SCAN_TIME
    print("[WEB-APP] Фоновый планировщик запущен.")
    
    while True:
        try:
            config = load_config()
            sched = config.get('scheduling', {})
            
            if sched.get('enabled'):
                interval = int(sched.get('interval_minutes', 60))
                if NEXT_SCAN_TIME is None:
                    NEXT_SCAN_TIME = datetime.now() + timedelta(minutes=interval)
                
                if datetime.now() >= NEXT_SCAN_TIME:
                    if SCAN_STATUS == "idle":
                        print(f"[SCHEDULER] Время пришло. Запуск планового сканирования...")
                        asyncio.create_task(background_scan_task())
                    NEXT_SCAN_TIME = datetime.now() + timedelta(minutes=interval)
                
                await asyncio.sleep(5)
            else:
                NEXT_SCAN_TIME = None
                await asyncio.sleep(10)
        except Exception as e:
            print(f"[SCHEDULER ERROR] {e}")
            await asyncio.sleep(10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения."""
    if not os.path.exists("config/config.yaml"):
        save_config(load_config())
    config = load_config()
    db_m = DatabaseManager(config['database']['path'])
    await db_m.init_db()
    scheduler_task = asyncio.create_task(periodic_scan_loop())
    yield
    scheduler_task.cancel()

app = FastAPI(title="CyberGuard Web Dashboard", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.get("/status")
async def get_status():
    config = load_config()
    enabled = config.get('scheduling', {}).get('enabled', False)
    if not enabled: next_val = "Выключен"
    elif NEXT_SCAN_TIME: next_val = NEXT_SCAN_TIME.strftime("%H:%M:%S")
    else: next_val = "Расчет..."
    
    return {"status": SCAN_STATUS, "next_scan": next_val, "is_enabled": enabled}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    results = []
    if os.path.exists(db_path):
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT ip, port, protocol, service, banner, vulns, timestamp FROM scan_results ORDER BY timestamp DESC") as cursor:
                results = await cursor.fetchall()

    st = await get_status()
    return templates.TemplateResponse(request, "index.html", {
        "config": config, "results": results, "is_scanning": (SCAN_STATUS == "scanning"),
        "next_scan": st["next_scan"], "active_page": "dashboard"
    })

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, saved: bool = False):
    config = load_config()
    return templates.TemplateResponse(request, "settings.html", {
        "config": config, "config_json": json.dumps(config, indent=4, ensure_ascii=False),
        "is_scanning": (SCAN_STATUS == "scanning"), "saved": saved, "active_page": "settings"
    })

@app.post("/settings/save")
async def save_all_settings(
    scanner_targets: str = Form(""), 
    scanner_ports: str = Form(""),
    scanner_rate: int = Form(1000), 
    scanner_interface: str = Form(""),
    tg_token: str = Form(""), 
    tg_chat_id: str = Form(""),
    vulners_key: str = Form(""), 
    sched_enabled: bool = Form(False),
    sched_interval: int = Form(60)
):
    global NEXT_SCAN_TIME
    current_cfg = load_config()
    new_cfg = {
        "scanner": {"targets": scanner_targets, "ports": scanner_ports, "rate": scanner_rate, "interface": scanner_interface},
        "telegram": {"token": tg_token, "chat_id": tg_chat_id},
        "vulners": {"api_key": vulners_key},
        "database": {"path": current_cfg['database']['path']},
        "scheduling": {"enabled": sched_enabled, "interval_minutes": sched_interval}
    }
    save_config(new_cfg)
    NEXT_SCAN_TIME = None
    return RedirectResponse(url="/settings?saved=true", status_code=303)

@app.post("/scan")
async def start_scan(targets: str = Form(...), ports: str = Form(...)):
    if SCAN_STATUS == "scanning": return RedirectResponse(url="/", status_code=303)
    config = load_config()
    config['scanner']['targets'], config['scanner']['ports'] = targets, ports
    save_config(config)
    asyncio.create_task(background_scan_task())
    return RedirectResponse(url="/", status_code=303)

@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    
    service_stats = {}
    security_stats = {"safe": 0, "vulnerable": 0}
    raw_data = [] # ПОЛНЫЙ СПИСОК ДЛЯ ФРОНТЕНДА
    
    if os.path.exists(db_path):
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT ip, port, service, vulns FROM scan_results") as cursor:
                async for row in cursor:
                    svc_full = row[2] if row[2] else "Unknown"
                    svc_main = svc_full.split()[0]
                    is_vulnerable = row[3] and "•" in str(row[3])
                    
                    # Группировка для графиков
                    service_stats[svc_main] = service_stats.get(svc_main, 0) + 1
                    if is_vulnerable: security_stats["vulnerable"] += 1
                    else: security_stats["safe"] += 1
                    
                    # Данные для JS-фильтрации
                    raw_data.append({
                        "ip": row[0],
                        "port": row[1],
                        "service": svc_main,
                        "vulnerable": "Уязвимы" if is_vulnerable else "Безопасны"
                    })

    return templates.TemplateResponse(request, "analytics.html", {
        "config": config,
        "service_labels": list(service_stats.keys()),
        "service_values": list(service_stats.values()),
        "sec_labels": ["Уязвимы", "Безопасны"],
        "sec_values": [security_stats["vulnerable"], security_stats["safe"]],
        "total_ports": len(raw_data),
        "raw_data_json": json.dumps(raw_data), # Передаем в JS
        "active_page": "analytics"
    })

@app.post("/results/clear")
async def clear_all_results():
    config = load_config()
    async with aiosqlite.connect(os.path.abspath(config['database']['path'])) as db:
        await db.execute("DELETE FROM scan_results"); await db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/results/delete")
async def delete_single_result(ip: str = Form(...), port: int = Form(...)):
    config = load_config()
    async with aiosqlite.connect(os.path.abspath(config['database']['path'])) as db:
        await db.execute("DELETE FROM scan_results WHERE ip=? AND port=?", (ip, port)); await db.commit()
    return RedirectResponse(url="/", status_code=303)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
