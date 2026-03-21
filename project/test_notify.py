import asyncio
import yaml
from src.notifier import TelegramNotifier

async def test():
    # Загружаем конфиг
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)

    # Инициализируем нотификатор
    notifier = TelegramNotifier(
        token=config['telegram']['token'], 
        chat_id=config['telegram']['chat_id']
    )

    print("Отправка тестового сообщения...")
    await notifier.send_message("🚀 <b>Система сканирования запущена!</b>\nУведомления работают корректно.")
    print("Готово! Проверь Telegram.")

if __name__ == "__main__":
    asyncio.run(test())
