# Importa bibliotecas necessárias
import requests  # Para requisições HTTP
import json      # Para manipulação de dados JSON
import os        # Para acessar variáveis de ambiente e arquivos locais
from datetime import datetime, timedelta  # Para lidar com datas e horários

# Busca a URL do webhook do Discord da variável de ambiente
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", None)
# Modo de simulação: se for True, apenas imprime no terminal sem enviar ao Discord
SIMULATION_MODE = os.environ.get("SIMULATE", "true").lower() == "true"
# Nome do arquivo de cache que armazena advisories já enviados
CACHE_FILE = "advisory_cache.json"
# URL da API da Broadcom para consultar os advisories de segurança da VMware
API_URL = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

# Filtros de severidade permitida
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
# Lista de produtos relevantes para monitoramento
ALLOWED_PRODUCTS = {
    "VMware Cloud Foundation", "VMware vCenter Server", "VMware ESXi",
    "VMware Tools", "VMware vSphere", "VMware Data Services Manager",
    "VMware NSX", "VMware Aria Suite", "VMware Aria Automation",
    "VMware Aria Automation with Orchestrator", "VMware Aria Operations",
    "VMware Aria Operations for logs", "VMware Aria Operations for Networks",
    "VMware Workspace ONE Access (Access)", "VMware Identity Manager (vIDM)"
}

# Quantidade de dias para filtrar advisories recentes
# ALLOWED_YEARS = {"2025"}  # Filtragem por ano 
DAYS_BACK = 10  # Filtro por data: últimos 10 dias

# Dicionário com códigos de cores baseados na severidade
COLOR_CODES = {
    "CRITICAL": 0xFF0000,    # Vermelho
    "HIGH": 0xFF8000,        # Laranja
    "MEDIUM": 0xFEFF00,      # Amarelo
    "LOW": 0x00FF00          # Verde
}

# Função para carregar o cache de advisories já enviados
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(json.load(f)) # Converte a lista salva em um set para busca rápida
    return set()

# Função para salvar o cache atualizado
def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(list(cache), f)

# Função que consulta a API da Broadcom para buscar os advisories
def get_advisories():
    payload = {"pageNumber": 0, "pageSize": 10, "searchVal": "", "segment": "VC"}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    r = requests.post(API_URL, headers=headers, json=payload)

    try:
        result = r.json()
        return result.get("data", {}).get("list", []) # Lista de advisories
    except Exception as e:
        print("❌ Erro ao interpretar JSON:", e)
        return []

# Função que envia a mensagem formatada para o Discord via Webhook
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

    # Concatena os produtos impactados em uma linha separados por vírgula (Não funcionando ainda)
    product_line = ", ".join([p.strip() for p in products.split(",") if p.strip()])

    # Estrutura do embed (mensagem enriquecida) para o Discord
    embed = {
        "title": f"{title_id}", # Ex: VMSA-2025-0013
        "url": link,
        "description": f"{title_full}\n\n\n", # Título completo com descrição
        "color": COLOR_CODES.get(severity, 0x808080), # Cor da borda do embed
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

    # Prepara o payload com o embed para envio
    payload = {"embeds": [embed]}

    # Se estiver em modo simulado ou a URL do webhook não estiver definida, imprime o conteúdo no terminal
    if SIMULATION_MODE or not WEBHOOK_URL:
        print("[SIMULAÇÃO] Payload para Discord:", json.dumps(payload, indent=2))
    else:
        response = requests.post(WEBHOOK_URL, json=payload)
        # Envia o payload para o Discord
        if response.status_code != 204:
            print(f"❌ Erro ao enviar para Discord: {response.status_code} - {response.text}")
    """
    # Confirma que a mensagem foi enviada com sucesso (código HTTP 204 = No Content)
    elif response.status_code == 204:
            print("✅ Mensagem padrão enviada com sucesso para o Discord.")
    """

# Verifica se o advisory atende aos filtros definidos
def matches_filters(advisory):
    severity = advisory.get("severity", "").upper()
    products = advisory.get("supportProducts", "")
    published = advisory.get("published", "")

    # Filtro por severidade
    if severity not in ALLOWED_SEVERITIES:
        return False
    
    # Filtro por produto relevante
    if not any(prod.lower() in products.lower() for prod in ALLOWED_PRODUCTS):
        return False

    # Filtro por data de publicação (últimos N dias)
    try:
        pub_date = datetime.strptime(published, "%d %B %Y")
        if pub_date < datetime.now() - timedelta(days=DAYS_BACK):
            return False
    except:
        return False

    return True

# Função principal
def main():
    cache = load_cache()
    advisories = get_advisories()

    new_cache = cache.copy()

    # Testes para corrigir o problema do cache local.
    """
    sent = False  # Flag para verificar se algum advisory foi enviado
    """

    for advisory in advisories:
        if isinstance(advisory, dict) and "documentId" in advisory:
            aid = advisory["documentId"]
            if aid not in cache and matches_filters(advisory):
                send_to_discord(advisory)  # Envia para o Discord
            #se falahar comentar essa linha abaido do sent = true
            sent = True  # Ao menos um advisory foi enviado
            new_cache.add(aid)  # Adiciona ao cache (mesmo se não enviar, garante que não será reprocessado)
        else:
            print("⚠️ Advisory inválido ou inesperado:", advisory)

    save_cache(new_cache) # Salva cache atualizado

    # Testes para corrigir o problema do cache local.
    """
  # Se nenhum advisory foi enviado, envia uma mensagem informativa
    if not sent:
        send_no_update_message()

# Função que envia uma mensagem ao Discord informando que não há novos advisories
def send_no_update_message():
    # Define a estrutura da mensagem embed com título, descrição e cor verde
    embed = {
        "title": "Nenhum novo Security Advisory",  # Título da mensagem
        "description": "✅ No momento, não há novos alertas de segurança VMware Broadcom.",  # Texto informativo
        "color": 0x00FF00  # Cor verde indicando status normal/sem alertas
    }

    
    # Prepara o payload com o embed para envio
    payload = {"embeds": [embed]}

    # Se estiver em modo simulado ou a URL do webhook não estiver definida, imprime o conteúdo no terminal
    if SIMULATION_MODE or not WEBHOOK_URL:
        print("[SIMULAÇÃO] Mensagem sem novos advisories:", json.dumps(payload, indent=2))
    else:
        # Envia o payload para o Discord
        response = requests.post(WEBHOOK_URL, json=payload)
        # Verifica se a resposta foi bem-sucedida
        if response.status_code != 204:
            print(f"❌ Erro ao enviar mensagem padrão: {response.status_code} - {response.text}")

        elif response.status_code == 204:
            print("✅ Mensagem padrão enviada com sucesso para o Discord.")

     """

# Executa se o script for chamado diretamente
if __name__ == "__main__":
    # main()
    main()
   # send_no_update_message()
