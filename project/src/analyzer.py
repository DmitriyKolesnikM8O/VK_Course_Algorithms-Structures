import asyncio

class ServiceAnalyzer:
    """
    Класс для быстрого получения приветственного сообщения (баннера) от сетевого сервиса.
    Реализует логику провокации (probing) для «молчаливых» протоколов типа HTTP.
    """

    def __init__(self, timeout=4.0):
        """
        Args:
            timeout (float): Максимальное время ожидания ответа от сокета.
        """
        
        self.timeout = timeout

    async def grab_banner(self, ip, port):
        """
        Пытается считать данные из TCP-сокета. 
        Для стандартных веб-портов отправляет пустой HTTP-запрос.
        
        Args:
            ip (str): IP-адрес цели.
            port (int): Порт цели.
            
        Returns:
            str: Очищенная строка баннера или описание ошибки.
        """
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
                        
            if port in [80, 443, 8080, 8443]:
                writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()

            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            banner_text = banner_bytes.decode('utf-8', errors='ignore').strip()            
            cleaned_banner = "".join(c for c in banner_text if c.isprintable() or c in "\n\r\t")
            
            return cleaned_banner[:200] if cleaned_banner else "No text banner (binary?)"
        
        except Exception:
            return "No banner (silent service)"
