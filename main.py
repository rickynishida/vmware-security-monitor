import requests
import json
import os

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", None)
SIMULATION_MODE = os.environ.get("SIMULATE", "true").lower() == "true"
CACHE_FILE = "advisory_cache.json"
API_URL = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(list(cache), f)

def get_advisories():
    payload = {"pageNumber": 0, "pageSize": 10, "searchVal": "", "segment": "VC"}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    r = requests.post(API_URL, headers=headers, json=payload)

    try:
        result = r.json()
        print("🔍 JSON recebido:", json.dumps(result, indent=2))
        return result.get("data", {}).get("list", [])
    except Exception as e:
        print("❌ Erro ao interpretar JSON:", e)
        return []

def send_to_discord(advisory):
    title = advisory.get("title", "Sem título")
    date = advisory.get("published", "Data desconhecida")
    link = advisory.get("notificationUrl") or "https://support.broadcom.com"
    msg = f"⚠️  **Novo VMware Advisory:**\n**{title}**\n📅 {date}\n🔗 {link}"

    if SIMULATION_MODE or not WEBHOOK_URL:
        print("[SIMULAÇÃO] Mensagem para o Discord:\n", msg)
    else:
        requests.post(WEBHOOK_URL, json={"content": msg})

def main():
    cache = load_cache()
    advisories = get_advisories()

    new_cache = cache.copy()

    for advisory in advisories:
        if isinstance(advisory, dict) and "documentId" in advisory:
            aid = advisory["documentId"]
            if aid not in cache:
                send_to_discord(advisory)
            new_cache.add(aid)
        else:
            print("⚠️ Advisory inválido ou inesperado:", advisory)

    save_cache(new_cache)

if __name__ == "__main__":
    main()
