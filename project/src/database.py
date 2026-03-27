import aiosqlite
from src.models import PortResult
from typing import List, Set

class DatabaseManager:
    """
    Класс для асинхронного взаимодействия с базой данных SQLite.
    Отвечает за инициализацию таблиц, хранение результатов и дедупликацию находок.
    """
    
    def __init__(self, db_path: str):
        """
        Args:
            db_path (str): Путь к файлу базы данных .db.
        """
        
        self.db_path = db_path

    async def init_db(self):
        """
        Создает таблицу scan_results, если она еще не существует.
        Использует составной первичный ключ (ip, port) для исключения дубликатов.
        """
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    banner TEXT,
                    vulns TEXT, 
                    timestamp DATETIME,
                    PRIMARY KEY (ip, port)
                )
            ''') 
            await db.commit()

    async def update_ports(self, results: List[PortResult]):
        """
        Сохраняет новые находки или обновляет существующие записи в БД.
        
        Args:
            results (List[PortResult]): Список объектов PortResult для записи.
        """
        
        async with aiosqlite.connect(self.db_path) as db:
            for res in results:
                await db.execute('''
                    INSERT OR REPLACE INTO scan_results (ip, port, protocol, service, banner, vulns, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (res.ip, res.port, res.protocol, res.service, res.banner, res.vulns, res.timestamp))
            await db.commit()

    async def get_all_known_ports(self) -> Set[tuple]:
        """
        Запрашивает из базы список всех ранее обнаруженных пар IP и порт.
        Используется для реализации Delta-сканирования (пропуск старых результатов).
        
        Returns:
            Set[tuple]: Множество кортежей вида (ip, port).
        """
        
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT ip, port FROM scan_results") as cursor:
                rows = await cursor.fetchall()
                return set(rows)
