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
ALLOWED_YEARS = {"2025"}  # você pode adaptar isso para incluir outras datas

COLOR_CODES = {
    "CRITICAL": 0xFF0000,  # Vermelho
    "HIGH": 0xFFA500,      # Laranja
    "MEDIUM": 0xFFFF00,    # Amarelo
    "LOW": 0x00FF00        # Verde
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
    title = advisory.get("title", "Sem título")
    advisory_id = advisory.get("documentId", "")
    severity = advisory.get("severity", "UNKNOWN").upper()
    products = advisory.get("supportProducts", "")
    link = advisory.get("notificationUrl") or "https://support.broadcom.com"
    date_published = advisory.get("published", "")
    formatted_date = datetime.strptime(date_published, "%d %B %Y").strftime("%d/%m/%Y") if date_published else ""
    cves = advisory.get("affectedCve", "")
    cvss_range = advisory.get("cvssRange", "N/A")
    updated_on = advisory.get("updated", "")[:10]

    product_lines = "\n".join(f"- {p.strip()}" for p in products.split(","))

    message = (
        f"**[{advisory_id}](<{link}>)**\n"
        f"{title}\n\n"
        f"**Advisory ID:** {advisory_id}\n"
        f"**Advisory Severity:** {severity}\n"
        f"**CVSS Base Score:** {cvss_range}\n"
        f"**Issue date:** {formatted_date}\n"
        f"**Updated on:** {updated_on} (Initial Advisory)\n"
        f"**CVE(s):** {cves}\n\n"
        f"**Impacted Products**\n{product_lines}"
    )

    payload = {
        "embeds": [
            {
                "description": message,
                "color": COLOR_CODES.get(severity, 0x808080)  # cinza default
            }
        ]
    }

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

    # Verifica severidade
    if severity not in ALLOWED_SEVERITIES:
        return False

    # Verifica produtos
    if not any(prod.lower() in products.lower() for prod in ALLOWED_PRODUCTS):
        return False

    # Verifica ano de publicação
    try:
        pub_date = datetime.strptime(published, "%d %B %Y")
        if str(pub_date.year) not in ALLOWED_YEARS:
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
