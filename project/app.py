import asyncio
import traceback
import yaml
import uvicorn
import aiosqlite
import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Импортируем нашу логику и менеджер БД
from main import run_single_scan
from src.database import DatabaseManager

app = FastAPI(title="CyberGuard Web Dashboard")
templates = Jinja2Templates(directory="templates")

SCAN_STATUS = "idle"

def load_config():
    """Загрузка конфигурации из YAML файла."""
    with open("config/config.yaml", "r") as f:
        return yaml.safe_load(f)

def save_config(config):
    """Сохранение конфигурации в YAML файл."""
    with open("config/config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

async def background_scan_task():
    """Фоновая задача сканирования."""
    global SCAN_STATUS
    SCAN_STATUS = "scanning"
    try:
        await run_single_scan()
    except Exception as e:
        print(f"[WEB-APP] Ошибка при сканировании: {e}")
        traceback.print_exc()
    finally:
        SCAN_STATUS = "idle"

@app.get("/status")
async def get_status():
    """Проверка статуса для JS."""
    return {"status": SCAN_STATUS}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Главная страница с таблицей."""
    config = load_config()
    db_path = os.path.abspath(config['database']['path'])
    
    results = []
    try:
        # ПРОВЕРКА: Если файла базы нет, таблица просто будет пустой
        if os.path.exists(db_path):
            async with aiosqlite.connect(db_path) as db:
                # Выбираем все 7 колонок
                async with db.execute(
                    "SELECT ip, port, protocol, service, banner, vulns, timestamp FROM scan_results ORDER BY timestamp DESC"
                ) as cursor:
                    results = await cursor.fetchall()
    except Exception as e:
        print(f"[WEB-APP] Ошибка при чтении БД: {e}")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "config": config,
        "results": results,
        "is_scanning": (SCAN_STATUS == "scanning")
    })

@app.post("/scan")
async def start_scan(targets: str = Form(...), ports: str = Form(...)):
    """Запуск сканирования из веб-формы."""
    global SCAN_STATUS
    if SCAN_STATUS == "scanning":
        return RedirectResponse(url="/", status_code=303)

    # Сохраняем настройки
    config = load_config()
    config['scanner']['targets'] = targets
    config['scanner']['ports'] = ports
    save_config(config)
    
    # Запуск в фоне
    asyncio.create_task(background_scan_task())
    return RedirectResponse(url="/", status_code=303)

async def init_system():
    """Инициализация базы данных перед стартом."""
    print("[WEB-APP] Инициализация базы данных...")
    config = load_config()
    db_m = DatabaseManager(config['database']['path'])
    await db_m.init_db()
    print("[WEB-APP] База данных готова.")

if __name__ == "__main__":
    # Сначала запускаем инициализацию базы (синхронно ждем её завершения)
    asyncio.run(init_system())
    
    # Затем запускаем сам сервер
    uvicorn.run(app, host="0.0.0.0", port=5000)
