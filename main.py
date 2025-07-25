import requests
import json
import os
from datetime import datetime, timedelta

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", None)
SIMULATION_MODE = os.environ.get("SIMULATE", "true").lower() == "true"
CACHE_FILE = "advisory_cache.json"
API_URL = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

# Filtros personalizáveis
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
ALLOWED_PRODUCTS = {
    "VMware Cloud Foundation", "VMware vCenter Server", "VMware ESXi",
    "VMware Tools", "VMware vSphere", "VMware Data Services Manager",
    "VMware NSX", "VMware Aria Suite", "VMware Aria Automation",
    "VMware Aria Automation with Orchestrator", "VMware Aria Operations",
    "VMware Aria Operations for logs", "VMware Aria Operations for Networks",
    "VMware Workspace ONE Access (Access)", "VMware Identity Manager (vIDM)"
}
# ALLOWED_YEARS = {"2025"}  # Filtragem por ano
DAYS_BACK = 10  # Filtro por data: últimos 10 dias

COLOR_CODES = {
    "CRITICAL": 0xFF0000,
    "HIGH": 0xFF8000,
    "MEDIUM": 0xFEFF00,
    "LOW": 0x00FF00
}

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
        return result.get("data", {}).get("list", [])
    except Exception as e:
        print("❌ Erro ao interpretar JSON:", e)
        return []

def send_to_discord(advisory):
    title_full = advisory.get("title", "Sem título")
    advisory_id = advisory.get("documentId", "")
    title_id = title_full.split(":")[0].strip()
    severity = advisory.get("severity", "UNKNOWN").upper()
    products = advisory.get("supportProducts", "")
    workaround = advisory.get("workAround", "None") or "None"
    link = advisory.get("notificationUrl") or "https://support.broadcom.com"
    date_published = advisory.get("published", "")
    formatted_date = datetime.strptime(date_published, "%d %B %Y").strftime("%d/%m/%Y") if date_published else ""
    cves = advisory.get("affectedCve", "")
    cvss_range = advisory.get("cvssRange", "N/A")
    updated_on = advisory.get("updated", "")[:10]

    product_line = ", ".join([p.strip() for p in products.split(",") if p.strip()])

    embed = {
        "title": f"{title_id}",
        "url": link,
        "description": f"{title_full}\n\n\n",
        "color": COLOR_CODES.get(severity, 0x808080),
        "fields": [
            {"name": "Advisory ID", "value": title_id, "inline": True},
            {"name": "Advisory Severity", "value": severity, "inline": True},
            {"name": "CVSS Base Score", "value": cvss_range, "inline": True},
            {"name": "Issue date", "value": formatted_date, "inline": True},
            {"name": "Updated on", "value": f"{updated_on} (Initial Advisory)", "inline": True},
            {"name": "Workaround", "value": workaround, "inline": True},
            {"name": "\u200b", "value": f"**CVE(s):** {cves or 'N/A'}\n", "inline": False},
            {"name": "Impacted Products", "value": product_line or "N/A", "inline": False}
        ]
    }

    payload = {"embeds": [embed]}

    if SIMULATION_MODE or not WEBHOOK_URL:
        print("[SIMULAÇÃO] Payload para Discord:", json.dumps(payload, indent=2))
    else:
        response = requests.post(WEBHOOK_URL, json=payload)
        if response.status_code != 204:
            print(f"❌ Erro ao enviar para Discord: {response.status_code} - {response.text}")

def matches_filters(advisory):
    severity = advisory.get("severity", "").upper()
    products = advisory.get("supportProducts", "")
    published = advisory.get("published", "")

    if severity not in ALLOWED_SEVERITIES:
        return False

    if not any(prod.lower() in products.lower() for prod in ALLOWED_PRODUCTS):
        return False

    try:
        pub_date = datetime.strptime(published, "%d %B %Y")
        if pub_date < datetime.now() - timedelta(days=DAYS_BACK):
            return False
    except:
        return False

    return True

def main():
    cache = load_cache()
    advisories = get_advisories()

    new_cache = cache.copy()

    for advisory in advisories:
        if isinstance(advisory, dict) and "documentId" in advisory:
            aid = advisory["documentId"]
            if aid not in cache and matches_filters(advisory):
                send_to_discord(advisory)
            new_cache.add(aid)
        else:
            print("⚠️ Advisory inválido ou inesperado:", advisory)

    save_cache(new_cache)

if __name__ == "__main__":
    main()
