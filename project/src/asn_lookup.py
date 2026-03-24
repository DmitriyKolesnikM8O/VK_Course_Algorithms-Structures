import httpx

class ASNResolver:
    @staticmethod
    async def get_prefixes(asn: str):
        asn_numeric = asn.upper().replace("AS", "").strip()
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_numeric}"
        print(f"[ASN] Запрос данных для AS{asn_numeric}...")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    prefixes = response.json().get("data", {}).get("prefixes", [])
                    ipv4 = [p['prefix'] for p in prefixes if ":" not in p['prefix']]
                    
                    # ДЛЯ ТЕСТА: берем только 3 подсети, чтобы не ждать вечность
                    if len(ipv4) > 3:
                        print(f"[ASN] Найдено {len(ipv4)} подсетей. Ограничиваем до 3 для скорости.")
                        ipv4 = ipv4[:3]
                    return ipv4
                return []
        except Exception as e:
            print(f"[ASN] Ошибка API: {e}")
            return []
