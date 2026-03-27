import asyncio
import vulners

class VulnersChecker:
    """
    Интерфейс для работы с официальным Vulners Python SDK.
    Реализует универсальный поиск CVE по названию и версии программного обеспечения.
    """
    
    def __init__(self, api_key: str):
        """
        Args:
            api_key (str): Ключ API Vulners (Free/Community план).
        """
        
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                self.client = vulners.VulnersApi(api_key=api_key)
            except AttributeError:
                try:
                    self.client = vulners.Vulners(api_key=api_key)
                except:
                    print("[!] Не удалось инициализировать Vulners SDK.")

    async def get_cves(self, software: str, version: str):
        """
        Выполняет асинхронный поиск уязвимостей в базе Vulners.
        Автоматически адаптируется под версию установленного SDK (find_all или search).
        
        Args:
            software (str): Название ПО (напр. 'openssl', 'apache').
            version (str): Версия ПО (напр. '1.0.1').
            
        Returns:
            list[str]: Список строк с ID уязвимостей и оценкой CVSS.
        """
        
        if not self.client or not software or software == "unknown" or not version:
            return []

        query = f"{software.lower()} {version}"
        print(f"[DEBUG] Запрос к Vulners: '{query}'")

        try:
            if hasattr(self.client, 'find_all'):
                results = await asyncio.to_thread(self.client.search.search_bulletins_all, query=query)
            
            elif hasattr(self.client, 'search'):
                if callable(self.client.search):
                    results = await asyncio.to_thread(self.client.search, query)
                else:
                    results = await asyncio.to_thread(self.client.search.search, query=query)
            else:
                return ["Метод поиска не найден в SDK"]

            cve_list = []
            if results:
                count = 0
                for item in results:
                    if count >= 5: break
                    
                    cve_id = item.get("id", "N/A")
                    cvss = item.get("cvss", {}).get("score", 0) if isinstance(item.get("cvss"), dict) else 0
                    cve_list.append(f"• {cve_id} (CVSS: {cvss})")
                    count += 1
                return cve_list
            return []
        except Exception as e:
            if "403" in str(e):
                print(f"[!] Vulners API 403: Доступ запрещен. Проверьте тариф Community на сайте.")
                return ["Ошибка 403: Проверьте подписку"]
            print(f"[!] Ошибка вызова SDK: {e}")
            return []
