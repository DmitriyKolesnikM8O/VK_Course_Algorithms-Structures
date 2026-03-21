import asyncio

class ServiceAnalyzer:
    def __init__(self, timeout=3.0):
        # Таймаут на ожидание ответа от сервиса
        self.timeout = timeout

    async def grab_banner(self, ip, port):
        """Пытается подключиться к порту и считать приветственный баннер."""
        try:
            # Устанавливаем асинхронное соединение
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            
            # Читаем первые 1024 байта (многие сервисы типа SSH/FTP шлют баннер сразу)
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            
            # Декодируем байты в строку, игнорируя ошибки кодировки
            return banner.decode('utf-8', errors='ignore').strip()
        
        except asyncio.TimeoutError:
            return "No banner (timeout)"
        except Exception as e:
            # Если сервис не шлет баннер первым (как HTTP), это не ошибка
            return f"No banner (service is silent)"
