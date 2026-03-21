import httpx

class TelegramNotifier:
    def __init__(self, token: str, chat_id: str):
        self.url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id

    async def send_message(self, text: str):
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML"
        }
        async with httpx.AsyncClient() as client:
            try:
                await client.post(self.url, json=payload)
            except Exception as e:
                print(f"[!] Error sending notification: {e}")
