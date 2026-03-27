import httpx

class ASNResolver:
    """
    Модуль для автоматического определения IP-диапазонов организации по её ASN.
    Использует открытое API RIPE NCC для получения актуальных данных BGP.
    """
    
    @staticmethod
    async def get_prefixes(asn: str):
        """
        Запрашивает анонсированные IPv4-префиксы автономной системы.
        
        Args:
            asn (str): Номер AS в формате 'AS123' или '123'.
            
        Returns:
            list[str]: Список подсетей в формате CIDR (напр. ['192.168.1.0/24']).
        """
        
        asn_numeric = asn.upper().replace("AS", "").strip()
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_numeric}"
        print(f"[ASN] Запрос данных для AS{asn_numeric}...")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    prefixes = response.json().get("data", {}).get("prefixes", [])
                    ipv4 = [p['prefix'] for p in prefixes if ":" not in p['prefix']]
                    
                    # берем только 3 подсети, чтобы не ждать вечность
                    if len(ipv4) > 3:
                        print(f"[ASN] Найдено {len(ipv4)} подсетей. Ограничиваем до 3 для скорости.")
                        ipv4 = ipv4[:3]
                    return ipv4
                return []
        except Exception as e:
            print(f"[ASN] Ошибка API: {e}")
            return []
