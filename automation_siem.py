import hashlib
import datetime
import requests
import json

# Chaves das APIs
VIRUS_TOTAL_API_KEY = '43878d7b0b28d0001a5d9429dad94f0e3fc32030404661c9da5368a7ea55841c'
ABUSE_IPDB_API_KEY = '8a7a31deb51388012929e8d5f2cdd236171d451621b1c27bbc459edbca2c5fd1fef4ff99ff334bbe'

# Configurações da API do VirusTotal
VIRUS_TOTAL_API = PublicApi(VIRUS_TOTAL_API_KEY)

# Configurações da API do AbuseIPDB
ABUSE_IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

# Configurações da API do Zabbix
ZABBIX_URL = 'http://localhost/zabbix/api_jsonrpc.php'
ZABBIX_USER = 'admin'
ZABBIX_PASSWORD = 'password'

# Configurações da API do OpenSearch
OPENSEARCH_URL = 'http://seu_opensearch_cluster:9200'
OPENSEARCH_INDEX = 'relatorios_logs'
OPENSEARCH_USERNAME = 'usuario'
OPENSEARCH_PASSWORD = 'senha'

# Função para consultar IP no AbuseIPDB
def check_ip(ip_address):
    headers = {
        'Key': ABUSE_IPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 0  # Consultar apenas o IP específico
    }
    try:
        response = requests.get(ABUSE_IPDB_URL, headers=headers, params=params)
        response.raise_for_status()  # Levanta um erro para códigos de status HTTP 4xx/5xx
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        return {'error': f'Erro HTTP ocorreu: {http_err}'}
    except Exception as err:
        return {'error': f'Outro erro ocorreu: {err}'}

# Função para coletar logs do Zabbix
def coletar_logs_zabbix():
    headers = {
        'Content-Type': 'application/json-rpc'
    }
    data = {
        'jsonrpc': '2.0',
        'method': 'event.get',
        'params': {
            'output': 'extend',
            'selectHosts': 'extend',
            'selectRelatedObject': 'extend',
            'selectTags': 'extend',
            'selectSuppressionData': 'extend',
            'sortfield': 'clock',
            'sortorder': 'DESC',
            'limit': 100
        },
        'id': 1,
        'auth': None
    }

    response = requests.post(ZABBIX_URL, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        eventos = response.json()['result']
        return eventos
    else:
        return None

# Função para processar os logs coletados
def processar_logs(eventos):
    ips = []
    for evento in eventos:
        # Extrai os IPs dos logs
        ip = evento['hosts'][0]['ip']
        ips.append(ip)

    return ips

# Função para processar o arquivo
def process_file(ips):
    abuse_results = []
    for ip in ips:
        result = check_ip(ip)
        abuse_results.append({
            'ip': ip,
            'result': result
        })

    # Salva os resultados do AbuseIPDB em um arquivo .txt
    nome_arquivo_abuse = "abuseipdbreport.txt"
    with open(nome_arquivo_abuse, 'w') as f:
        for result in abuse_results:
            f.write(f"IP: {result['ip']}\n")
            if 'error' in result['result']:
                f.write(f"Erro: {result['result']['error']}\n")
            else:
                f.write(f"Resposta: {result['result']}\n")
            f.write('\n')

    # Envia os relatórios para o OpenSearch
    send_to_opensearch(abuse_results)

# Função para enviar os relatórios para o OpenSearch
def send_to_opensearch(abuse_results):
    url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_doc"
    headers = {'Content-Type': 'application/json'}
    
    for result in abuse_results:
        document = {
            'ip': result['ip'],
            'result': result['result'],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            response = requests.post(url, auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD), headers=headers, data=json.dumps(document))
            response.raise_for_status()
            print(f"Documento enviado com sucesso: {response.json()}")
        except requests.exceptions.HTTPError as http_err:
            print(f"Erro HTTP ao enviar documento: {http_err}")
        except Exception as err:
            print(f"Erro geral ao enviar documento: {err}")

# Exemplo de uso
eventos = coletar_logs_zabbix()
if eventos:
    ips = processar_logs(eventos)
    process_file(ips)
else:
    print("Nenhum log coletado.")
