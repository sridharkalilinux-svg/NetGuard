import requests
import logging

logger = logging.getLogger(__name__)

# Simple in-memory cache
GEO_CACHE = {}

def is_private_ip(ip):
    # Check for private IP ranges (RFC 1918)
    try:
        parts = list(map(int, ip.split('.')))
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if ip == '127.0.0.1': return True
    except:
        pass
    return False

def resolve_ip(ip):
    """
    Resolves IP to location using ip-api.com (Free, Rate Limited).
    """
    if not ip or is_private_ip(ip):
        return None
        
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        # Note: ip-api.com is free for non-commercial use, 45 req/min.
        # In a real production system, you'd use a paid API or local DB (MMDB).
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=1)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                info = {
                    'ip': ip,
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'org': data.get('org')
                }
                GEO_CACHE[ip] = info
                return info
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {e}")
    
    return None

def resolve_batch(ips):
    """
    Resolves a list of IPs. respecting rate limits roughly.
    """
    results = []
    count = 0
    for ip in ips:
        if count > 40: break # Safety break for demo to avoid ban
        res = resolve_ip(ip)
        if res:
            results.append(res)
            count += 1
    return results
