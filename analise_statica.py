import os
import re

PADROES = {
  
   
    "redirect aberto": r"redirect\((request\.GET|url)\)",
    "parâmetro direto": r"(request\.GET|request\.POST|\$_GET|\$_POST)",
    "session insegura": r"(session\.cookie_secure\s*=\s*False)",
    "header ausente": r"(X-Frame-Options|Content-Security-Policy)",
    "atribuição de chave sensível": r"\$(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\s*=\s*[\"']\s*[a-zA-Z0-9]+[\"']",
    "sensitive_paths": r"(/admin|/config|/backup|/private|/usuario|/usuarios|/cliente|/clientes|/produto|/produtos|/pedidos|/pedido|/ordem|/ordens|/comissoes|/comissão|/acesso|/painel|/controllers|/css|/dist|/imgs|/img|/plugins)",
    "xss": r"(document\.write|innerHTML\s*=|<script>|onerror\s*=|onload\s*=)",
    "hardcoded api key": r"(api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",

    # Injeção de SQL
    "sql injection": r"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*([\"']?\s*\.\s*\$?\w+\s*\.\s*[\"']?|[\"']\s*\$?\w+\s*[\"'])",

    # Verificação de role ausente
    "verificação de role ausente": r"(if\s+user\.role\s*==\s*['\"]admin['\"])?",

    # Variável sensível com valor nulo ou vazio
    "variavel null": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*(\"\"|\'\')",

    # Atribuição direta de chave sensível com valor não vazio
    "atribuição de chave sensível": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*[\"']\s*[a-zA-Z0-9@#\$%\^&\*\-]{4,}[\"']",

    # XSS (Cross-Site Scripting)
    "xss": r"(document\.write|innerHTML\s*=|<script>|onerror\s*=|onload\s*=|dangerouslySetInnerHTML)",

    # Hardcoded API Key
    "hardcoded api key": r"(api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",

    # Hardcoded certificado ou chave privada
    "hardcoded certificado": r"(BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY)",

    "variavel com valor vazio ou null": r"\b\w+\b\s*=\s*(\"\"|\'\'|null)",

    "criptografia fraca por fórmula": r"\b(pass|key|token|secret)\b\s*=\s*\w+\s*[\+\-\*/\^%]\s*\w+",

    "uso de algoritmo inseguro": r"\b(md5|sha1|base64|rot13|crc32)\b\s*\(",
    "login sem hash": r"(password\s*==\s*\".*\")|(senha\s*==\s*\".*\")",
    "comparação de senha insegura": r"(if\s+\w+\s*==\s*\w+)",
    "token estático": r"(auth_token|jwt|session_id)\s*=\s*[\"'][A-Za-z0-9\-_]{8,}[\"']",
    "autenticação sem hash": r"\b(password|senha)\b\s*=\s*[\"'][a-zA-Z0-9@#\$%\^&\*\-]{4,}[\"']",
    "login sem criptografia": r"(login|authenticate)\s*\(.*\)\s*{[^}]*password\s*==",
    "token fixo": r"\b(token|session_id|jwt)\b\s*=\s*[\"'][A-Za-z0-9\-_]{8,}[\"']",
    "falta de sanitização": r"(input|request\.GET|request\.POST|req\.body|req\.query)\s*(?!.*sanitize)",
    "uso de eval": r"\b(eval|exec|Function)\s*\(",
    "uso de regex inseguro": r"(re\.match|re\.search|Pattern\.compile)\s*\(.*\*\)",
    "leitura de arquivo sem validação": r"(open\s*\(|fs\.readFile\s*\(|FileReader\s*\()",
    "upload sem restrição": r"(move_uploaded_file|file\.upload|req\.files)",
    "listagem de diretório": r"(os\.listdir|readdir\s*\(|dir\s*\()",
    "execução de comando": r"(os\.system|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec)",
    "comando concatenado": r"(exec\s*\(\s*\".*\"\s*\+\s*\w+)",
    "uso de algoritmo inseguro": r"\b(md5|sha1|base64|rot13|crc32)\b\s*\(",
    "criptografia fraca por fórmula": r"\b(pass|key|token|secret)\b\s*=\s*\w+\s*[\+\-\*/\^%]\s*\w+",
    "desativação de verificação SSL": r"(verify\s*=\s*False|ssl\.verify\s*=\s*False)",
    "exceção genérica": r"(except\s*Exception\s*as\s*\w+:|catch\s*\(Exception\s+\w+\))",
    "debug ativo": r"(debug\s*=\s*True|console\.log|print\s*\()",
    "comentário com senha": r"(#.*senha|//.*password|/\*.*secret)",
    

}


EXTENSOES_SUPORTADAS = [".py", ".js", ".php", ".java"]

def analisar(caminho_projeto):
    achados = []
    for raiz, _, arquivos in os.walk(caminho_projeto):
        for arquivo in arquivos:
            ext = os.path.splitext(arquivo)[1].lower()
            if ext in EXTENSOES_SUPORTADAS:
                caminho = os.path.join(raiz, arquivo)
                try:
                    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                        conteudo = f.read()
                        for nome, padrao in PADROES.items():
                            for i, linha in enumerate(conteudo.splitlines(), start=1):
                                if re.search(padrao, linha, re.IGNORECASE):
                                    achados.append((caminho, f"Linha {i}: Possível vulnerabilidade: {nome}"))
                                    break
                except Exception as e:
                    achados.append((caminho, f"Erro ao analisar: {str(e)}"))
    return achados

def detectar_rotas_sem_autenticacao(conteudo):
    achados = []
    linhas = conteudo.splitlines()
    for i in range(len(linhas)):
        linha = linhas[i].strip()
        if linha.startswith("def ") and i > 0:
            decorador = linhas[i - 1].strip()
            if not decorador.startswith("@login_required"):
                achados.append(f"Linha {i+1}: rota sem autenticação")
    return achados
