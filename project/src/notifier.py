import httpx

class TelegramNotifier:
    """
    Класс для взаимодействия с Telegram Bot API.
    Отвечает за отправку форматированных HTML-отчетов пользователю.
    """
    
    def __init__(self, token: str, chat_id: str):
        """
        Args:
            token (str): API токен бота от @BotFather.
            chat_id (str): ID чата получателя.
        """
        
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id

    async def send_message(self, text: str):
        """
        Отправляет текстовое сообщение с поддержкой HTML.
        Автоматически обрезает слишком длинные сообщения (лимит Telegram 4096 симв).
        """
        
        if len(text) > 4000:
            text = text[:3900] + "\n... (сообщение обрезано)"

        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.url, json=payload, timeout=15.0)
                if response.status_code != 200:
                    print(f"[!] Telegram Error {response.status_code}: {response.text}")
                return response
            except Exception as e:
                print(f"[!] Ошибка отправки уведомления: {e}")
