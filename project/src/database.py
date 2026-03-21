import aiosqlite
from src.models import PortResult
from typing import List, Set

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init_db(self):
        """Создает таблицу, если она еще не существует."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    banner TEXT,
                    timestamp DATETIME,
                    PRIMARY KEY (ip, port)
                )
            ''')
            await db.commit()

    async def get_all_known_ports(self) -> Set[tuple]:
        """Возвращает сет кортежей (ip, port) всех ранее обнаруженных портов."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT ip, port FROM scan_results") as cursor:
                rows = await cursor.fetchall()
                return set(rows)

    async def update_ports(self, results: List[PortResult]):
        """Обновляет или вставляет новые результаты в базу."""
        async with aiosqlite.connect(self.db_path) as db:
            for res in results:
                await db.execute('''
                    INSERT OR REPLACE INTO scan_results (ip, port, protocol, service, banner, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (res.ip, res.port, res.protocol, res.service, res.banner, res.timestamp))
            await db.commit()
