import asyncio
import yaml
from src.cve_checker import VulnersChecker

async def test():
    """
    Скрипт для тестирования работоспособности Vulners API ключа.
    Запрашивает данные для заведомо уязвимой версии OpenSSL 1.0.1.
    """
    
    with open("config/config.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    key = config.get('vulners', {}).get('api_key', '')
    checker = VulnersChecker(api_key=key)
    
    print(f"Тестируем ключ: {key[:10]}...")
    results = await checker.get_cves("openssl", "1.0.1")
    
    if results:
        print("уСПЕХ! Найдены уязвимости:")
        for r in results:
            print(r)
    else:
        print("ОШИБКА или ничего не найдено. Проверь логи выше.")

if __name__ == "__main__":
    asyncio.run(test())
