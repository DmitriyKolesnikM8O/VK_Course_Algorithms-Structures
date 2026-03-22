import asyncio

class ServiceAnalyzer:
    def __init__(self, timeout=4.0):
        self.timeout = timeout

    async def grab_banner(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            
            # Если это веб-порт, пошлем пустой запрос, чтобы сервер ответил
            if port in [80, 443, 8080, 8443]:
                writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()

            # Ждем ответа
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()

            # Чистим баннер от бинарного мусора
            banner_text = banner_bytes.decode('utf-8', errors='ignore').strip()
            # Оставляем только читаемые символы (чтобы не было мусора как на порту 9929)
            cleaned_banner = "".join(c for c in banner_text if c.isprintable() or c in "\n\r\t")
            
            return cleaned_banner[:200] if cleaned_banner else "No text banner (binary?)"
        
        except Exception:
            return "No banner (silent service)"
