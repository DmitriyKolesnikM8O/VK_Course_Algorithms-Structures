from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class PortResult(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = "unknown"
    banner: Optional[str] = ""
    timestamp: datetime = datetime.now()

    def __hash__(self):
        # Хэш по IP и порту, чтобы легко сравнивать объекты
        return hash((self.ip, self.port))

    def __eq__(self, other):
        if not isinstance(other, PortResult):
            return False
        return self.ip == other.ip and self.port == other.port
