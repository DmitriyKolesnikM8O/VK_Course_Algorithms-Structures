from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class PortResult(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = "unknown"
    banner: Optional[str] = ""
    vulns: Optional[str] = "" # Это поле для CVE
    timestamp: datetime = datetime.now()

    def __hash__(self):
        return hash((self.ip, self.port))

    def __eq__(self, other):
        if not isinstance(other, PortResult):
            return False
        return self.ip == other.ip and self.port == other.port
