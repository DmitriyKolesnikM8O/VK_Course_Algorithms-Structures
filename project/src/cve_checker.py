import asyncio
import vulners

class VulnersChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                # Пробуем классический конструктор
                self.client = vulners.VulnersApi(api_key=api_key)
            except AttributeError:
                try:
                    # Пробуем новый конструктор
                    self.client = vulners.Vulners(api_key=api_key)
                except:
                    print("[!] Не удалось инициализировать Vulners SDK.")

    async def get_cves(self, software: str, version: str):
        """Пытается найти CVE через любой доступный метод SDK."""
        if not self.client or not software or software == "unknown" or not version:
            return []

        # Максимально простой запрос (просто строка)
        query = f"{software.lower()} {version}"
        print(f"[DEBUG] Запрос к Vulners: '{query}'")

        try:
            # Метод 1: find_all (самый стабильный, хоть и с варнингом)
            if hasattr(self.client, 'find_all'):
                results = await asyncio.to_thread(self.client.search.search_bulletins_all, query=query)
            
            # Метод 2: Если find_all нет, пробуем search
            elif hasattr(self.client, 'search'):
                # Проверяем, это метод или объект (как было в твоей ошибке)
                if callable(self.client.search):
                    results = await asyncio.to_thread(self.client.search, query)
                else:
                    # Если это объект, пробуем вызвать вложенный поиск
                    results = await asyncio.to_thread(self.client.search.search, query=query)
            else:
                return ["Метод поиска не найден в SDK"]

            # Обработка результатов
            cve_list = []
            if results:
                # Так как теперь это итератор, просто берем первые 5 элементов через цикл
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
