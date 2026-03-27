from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class PortResult(BaseModel):
    """
    Pydantic-модель для представления результата сканирования одного порта.
    Обеспечивает типизацию и удобную сериализацию данных.
    """
    
    ip: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = "unknown"
    banner: Optional[str] = ""
    vulns: Optional[str] = "" 
    timestamp: datetime = datetime.now()

    def __hash__(self):
        """
        Хэширование по паре IP:Port для использования в set (дедупликация).
        """
        
        return hash((self.ip, self.port))

    def __eq__(self, other):
        """
        Сравнение объектов по паре IP:Port.
        """
        
        if not isinstance(other, PortResult):
            return False
        return self.ip == other.ip and self.port == other.port
