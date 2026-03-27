import csv
import io
import asyncio
import traceback
import yaml
import uvicorn
import aiosqlite
import os
import json
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from main import main as scan_logic
from src.database import DatabaseManager

# ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ СОСТОЯНИЯ
SCAN_STATUS = "idle"
NEXT_SCAN_TIME = None
CURRENT_TASK = None
PROGRESS = {"current": 0, "total": 0, "ip": ""}

def load_config():
    """
    Загружает конфигурацию из config/config.yaml.
    Если файл отсутствует, возвращает словарь с дефолтными значениями.
    Выполняет рекурсивное слияние с дефолтами для предотвращения KeyError.
    """
    
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
    
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for sk, sv in value.items():
                if sk not in config[key]:
                    config[key][sk] = sv
    return config

def save_config(config):
    """
    Сохраняет переданный словарь конфигурации в файл config/config.yaml в формате YAML.
    """
    
    os.makedirs("config", exist_ok=True)
    with open("config/config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def update_progress(current, total, ip):
    """
    Callback-функция для обновления глобального прогресса сканирования.
    Вызывается из модуля main.py во время анализа найденных портов.
    """
    
    global PROGRESS
    PROGRESS["current"] = current
    PROGRESS["total"] = total
    PROGRESS["ip"] = ip

async def background_scan_task():
    """
    Корутина для запуска логики сканирования в фоновом режиме.
    Управляет статусом SCAN_STATUS и сбрасывает PROGRESS по завершении.
    Поддерживает обработку исключения принудительной остановки (asyncio.CancelledError).
    """
    
    global SCAN_STATUS, PROGRESS
    if SCAN_STATUS == "scanning": return
    SCAN_STATUS = "scanning"
    PROGRESS = {"current": 0, "total": 0, "ip": "Masscan..."}
    print(f"[PROCESS] Сканирование начато: {datetime.now().strftime('%H:%M:%S')}")
    try:
        await scan_logic(progress_callback=update_progress)
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        traceback.print_exc()
    finally:
        SCAN_STATUS = "idle"
        PROGRESS = {"current": 0, "total": 0, "ip": ""}
        print(f"[PROCESS] Сканирование завершено.")

async def periodic_scan_loop():
    """
    Бесконечный цикл планировщика задач. 
    Раз в 5 секунд проверяет, не пора ли запустить сканирование по расписанию.
    """
    
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
    """
    Управляет жизненным циклом приложения: выполняется при старте и остановке сервера.
    Инициализирует БД и запускает планировщик.
    """
    
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

# ENDPOINTS

@app.get("/status")
async def get_status():
    """
    Возвращает текущий статус сканера и прогресс для AJAX-запросов фронтенда.
    """
    
    config = load_config()
    enabled = config.get('scheduling', {}).get('enabled', False)
    next_val = NEXT_SCAN_TIME.strftime("%H:%M:%S") if NEXT_SCAN_TIME else ("Выключен" if not enabled else "Запуск...")    
    return {"status": SCAN_STATUS, "next_scan": next_val, "is_enabled": enabled, "progress": PROGRESS}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Главная страница: отображает Дашборд с результатами сканирования.
    """
    
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
    """
    Страница настроек: позволяет редактировать конфигурацию.
    """
    
    config = load_config()
    return templates.TemplateResponse(request, "settings.html", {
        "config": config, "config_json": json.dumps(config, indent=4, ensure_ascii=False),
        "is_scanning": (SCAN_STATUS == "scanning"), "saved": saved, "active_page": "settings"
    })

@app.post("/scan")
async def start_scan(targets: str = Form(...), ports: str = Form(...)):
    """
    Принимает форму с дашборда и запускает ручное сканирование.
    """
    
    global CURRENT_TASK
    if SCAN_STATUS == "scanning": return RedirectResponse(url="/", status_code=303)
    config = load_config()
    config['scanner']['targets'], config['scanner']['ports'] = targets, ports
    save_config(config)
    
    CURRENT_TASK = asyncio.create_task(background_scan_task())
    return RedirectResponse(url="/", status_code=303)

@app.post("/scan/stop")
async def stop_scan():
    """
    Прерывает выполнение текущей задачи сканирования через CancelledError.
    """
    
    global CURRENT_TASK
    if CURRENT_TASK and not CURRENT_TASK.done():
        CURRENT_TASK.cancel()
    return RedirectResponse(url="/", status_code=303)

@app.get("/export/csv")
async def export_csv():
    """
    Генерирует и отдает CSV-файл со всеми результатами из БД.
    """
    
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Port", "Protocol", "Service", "Banner", "Vulnerabilities", "Timestamp"])
    
    if os.path.exists(db_path):
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT * FROM scan_results") as cursor:
                async for row in cursor:
                    writer.writerow(row)
    
    output.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=scan_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"}
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)

@app.get("/export/json")
async def export_json():
    """
    Генерирует и отдает красиво отформатированный JSON-файл с результатами.
    """
    
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    data = []
    if os.path.exists(db_path):
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT * FROM scan_results") as cursor:
                async for row in cursor:
                    data.append({
                        "ip": row[0], "port": row[1], "protocol": row[2],
                        "service": row[3], "banner": row[4], "vulns": row[5],
                        "timestamp": row[6]
                    })
    
    json_pretty = json.dumps(data, indent=4, ensure_ascii=False)
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return Response(content=json_pretty, media_type="application/json", headers=headers)

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
    """
    Принимает данные из формы настроек и обновляет config.yaml.
    """
    
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


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """
    Страница аналитики: агрегирует данные и передает их для отрисовки графиков Chart.js.
    """
    
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    
    service_stats = {}
    security_stats = {"safe": 0, "vulnerable": 0}
    raw_data = [] 
    
    if os.path.exists(db_path):
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT ip, port, service, vulns FROM scan_results") as cursor:
                async for row in cursor:
                    svc_full = row[2] if row[2] else "Unknown"
                    svc_main = svc_full.split()[0]
                    is_vulnerable = row[3] and "•" in str(row[3])
                    
                    
                    service_stats[svc_main] = service_stats.get(svc_main, 0) + 1
                    if is_vulnerable: security_stats["vulnerable"] += 1
                    else: security_stats["safe"] += 1
                    
                    
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
        "raw_data_json": json.dumps(raw_data), 
        "active_page": "analytics"
    })

@app.post("/results/clear")
async def clear_all_results():
    """
    Очищает всю таблицу результатов в базе данных.
    """
    
    config = load_config()
    async with aiosqlite.connect(os.path.abspath(config['database']['path'])) as db:
        await db.execute("DELETE FROM scan_results"); await db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/results/delete")
async def delete_single_result(ip: str = Form(...), port: int = Form(...)):
    """
    Удаляет конкретную запись из БД по паре IP и Порт.
    """
    
    config = load_config()
    async with aiosqlite.connect(os.path.abspath(config['database']['path'])) as db:
        await db.execute("DELETE FROM scan_results WHERE ip=? AND port=?", (ip, port)); await db.commit()
    return RedirectResponse(url="/", status_code=303)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
