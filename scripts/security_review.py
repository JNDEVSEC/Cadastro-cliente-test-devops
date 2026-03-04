#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom Security Review (enhanced + STRIDE + Attack mapping)
- Para cada achado, inclui: vulnerabilidade, risco, correção/mitigação,
  STRIDE, tipo(s) de ataque, OWASP Top 10 e MITRE ATT&CK (quando aplicável).
- Exporta JSON, CSV (colunas extra) e SARIF com help markdown enriquecido.
"""

import argparse
import csv
import json
import os
import re
import sys
from typing import Dict, List, Iterable

# -----------------------
# Configuração principal (defaults)
# -----------------------
DEFAULT_EXTS = [".py", ".js", ".php", ".java", ".ts", ".jsx", ".tsx"]
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
    "node_modules", "dist", "build", "out", ".venv", "venv", "__pycache__",
    ".next", ".nuxt", ".yarn", ".pnpm-store", "coverage", "scripts"
}
DEFAULT_MAX_BYTES = 1_000_000  # 1 MB por arquivo

# Severidade -> nível SARIF
SEV_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Ordem de severidades
SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def sev_gte(a: str, b: str) -> bool:
    return SEV_ORDER.index(a) >= SEV_ORDER.index(b)

# -----------------------
# Regras (ID, nome, regex, severidade)
# -----------------------
RULES = [
    # Exposição/segredos
    {"id": "SRV-001", "name": "hardcoded api key", "re": r"(api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "sev": "CRITICAL"},
    {"id": "SRV-002", "name": "hardcoded certificado/chave privada", "re": r"(BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY)", "sev": "CRITICAL"},
    {"id": "SRV-003", "name": "atribuição de chave/segredo", "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*['\"][^'\"]{4,}['\"]", "sev": "HIGH"},
    {"id": "SRV-004", "name": "variável sensível vazia/nula", "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*([\"']{2}|null|None)", "sev": "MEDIUM"},

    # Autenticação/autorização
    {"id": "SRV-010", "name": "redirect aberto", "re": r"redirect\((request\.GET|url)\)", "sev": "HIGH"},
    {"id": "SRV-011", "name": "uso direto de parâmetro do request", "re": r"(request\.GET|request\.POST|\$_GET|\$_POST)", "sev": "LOW"},

    # Criptografia/algoritmos
    {"id": "SRV-020", "name": "uso de hash/algoritmo inseguro", "re": r"\b(md5|sha1|rot13|crc32)\b\s*\(", "sev": "HIGH"},
    {"id": "SRV-021", "name": "base64 tratado como criptografia", "re": r"\bbase64\b\s*\(", "sev": "MEDIUM"},
    {"id": "SRV-022", "name": "criptografia fraca por fórmula", "re": r"\b(pass|key|token|secret)\b\s*=\s*\w+\s*[\+\-\*/\^%]\s*\w+", "sev": "MEDIUM"},

    # Injeções / Execução
    {"id": "SRV-030", "name": "sql injection (heurístico)", "re": r"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*(['\"]?\s*\.\s*\$?\w+\s*\.\s*['\"]?|['\"]\s*\$?\w+\s*['\"])", "sev": "HIGH"},
    {"id": "SRV-031", "name": "uso de eval/exec", "re": r"\b(eval|exec|Function)\s*\(", "sev": "HIGH"},
    {"id": "SRV-032", "name": "execução de comando do SO", "re": r"(os\.system|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec)", "sev": "HIGH"},
    {"id": "SRV-033", "name": "comando concatenado", "re": r"(exec\s*\(\s*\".*\"\s*\+\s*\w+)", "sev": "MEDIUM"},

    # Entrada/arquivos/rede
    {"id": "SRV-040", "name": "leitura de arquivo sem validação", "re": r"(open\s*\(|fs\.readFile\s*\(|FileReader\s*\()", "sev": "LOW"},
    {"id": "SRV-041", "name": "upload sem restrição", "re": r"(move_uploaded_file|file\.upload|req\.files)", "sev": "HIGH"},
    {"id": "SRV-042", "name": "listagem de diretório", "re": r"(os\.listdir|readdir\s*\(|\bdir\s*\()", "sev": "LOW"},

    # HTTP/Headers/Sessão
    {"id": "SRV-050", "name": "session.cookie_secure=False", "re": r"session\.cookie_secure\s*=\s*False", "sev": "HIGH"},
    {"id": "SRV-051", "name": "header de segurança ausente (menção)", "re": r"(X-Frame-Options|Content-Security-Policy)", "sev": "INFO"},
    {"id": "SRV-052", "name": "desativação de verificação SSL", "re": r"(verify\s*=\s*False|ssl\.verify\s*=\s*False)", "sev": "HIGH"},

    # XSS
    {"id": "SRV-060", "name": "XSS (dangerous sink)", "re": r"(document\.write|innerHTML\s*=|<script>|onerror\s*=|onload\s*=|dangerouslySetInnerHTML)", "sev": "HIGH"},

    # Qualidade/Práticas
    {"id": "SRV-070", "name": "exceção genérica", "re": r"(except\s+Exception\b|catch\s*\(Exception\b)", "sev": "LOW"},
    {"id": "SRV-071", "name": "debug ativo", "re": r"(debug\s*=\s*True|console\.log|print\s*\()", "sev": "LOW"},
    {"id": "SRV-072", "name": "comentário com senha/secret", "re": r"(#.*senha|//.*password|/\*.*secret)", "sev": "LOW"},

    # Caminhos sensíveis
    {"id": "SRV-080", "name": "paths sensíveis expostos (menção)", "re": r"(/admin|/config|/backup|/private|/usuario(s)?|/cliente(s)?|/produto(s)?|/pedidos?|/ordem(s)?|/comiss(o|õ)es?|/acesso|/painel|/controllers|/css|/dist|/img(s)?|/plugins)", "sev": "INFO"},

    # Rotas (heurística Python)
    {"id": "SRV-090", "name": "rota sem autenticação (heurístico)", "re": r"", "sev": "HIGH"},
]

# -----------------------
# Metadados por regra (agora com STRIDE, attack_types, explanation, mitigation, OWASP, ATT&CK)
# -----------------------
RULE_META: Dict[str, Dict] = {
    # Exposição/segredos
    "SRV-001": {
        "cwe": ["CWE-798"],
        "vulnerability": "Credenciais/API Keys hardcoded expostas no código",
        "risk": "Acesso não autorizado a serviços/dados, pivot e abuso de quotas.",
        "remediation": "Remover do código; usar secret manager/env; rotacionar chaves comprometidas.",
        "mitigation": "Implementar varredura de segredos no CI/CD e enforcement de políticas (pre-commit).",
        "explanation": "Chaves no repositório possibilitam intrusos reutilizarem credenciais em APIs/serviços.",
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "attack_types": ["Credential Exposure", "Secret Leakage"],
        "owasp": ["A02:2021 - Cryptographic Failures", "A04:2021 - Insecure Design"],
        "attck": ["T1552"],  # Unsecured Credentials
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    "SRV-002": {
        "cwe": ["CWE-321"],
        "vulnerability": "Chave privada/certificado embutido no repositório",
        "risk": "Impersonation/MITM; decriptação e forja de tráfego.",
        "remediation": "Nunca commitar chaves/certs; armazenar em vault/KMS; rotacionar imediatamente.",
        "mitigation": "Assinar e rotacionar chaves; escanear histórico do VCS e revogar credenciais.",
        "explanation": "Com a chave privada, o atacante pode se passar pelo serviço legítimo.",
        "stride": ["Spoofing", "Information Disclosure"],
        "attack_types": ["Credential Exposure", "Impersonation"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": ["T1552"],
        "references": ["https://cwe.mitre.org/data/definitions/321.html"],
    },
    "SRV-003": {
        "cwe": ["CWE-798", "CWE-312"],
        "vulnerability": "Atribuição de segredo sensível em texto plano",
        "risk": "Vazamento via VCS/logs e comprometimento de contas/serviços.",
        "remediation": "Gerir segredos externamente; remover do código; revisar histórico de commits.",
        "mitigation": "Aplicar políticas de prevenção de commit de segredos e rotação automatizada.",
        "explanation": "Segredos embutidos podem ser extraídos por adversários e reutilizados.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Credential Exposure", "Secret Leakage"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": ["T1552"],
        "references": ["https://cwe.mitre.org/data/definitions/312.html"],
    },
    "SRV-004": {
        "cwe": ["CWE-200"],
        "vulnerability": "Configuração de segredo vazio/nulo",
        "risk": "Quedas para defaults inseguros e bypass de controles.",
        "remediation": "Obrigar preenchimento/validação; falhar build/deploy se ausente.",
        "mitigation": "Policies-as-code e testes negativos em CI.",
        "explanation": "Segredos ausentes podem desativar proteções, expondo dados ou endpoints.",
        "stride": ["Tampering", "Elevation of Privilege"],
        "attack_types": ["Misconfiguration", "AuthN Weakness"],
        "owasp": ["A05:2021 - Security Misconfiguration"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # Autenticação/autorização
    "SRV-010": {
        "cwe": ["CWE-601"],
        "vulnerability": "Open Redirect",
        "risk": "Phishing, roubo de sessão e chaining de ataques.",
        "remediation": "Allowlist de destinos; normalização do URL; não confiar em parâmetros do usuário.",
        "mitigation": "Bloquear redirecionamentos externos não autorizados; logs/alertas.",
        "explanation": "Redirecionamentos controlados por usuário permitem enviar vítimas a domínios maliciosos.",
        "stride": ["Spoofing"],
        "attack_types": ["Open Redirect", "Phishing"],
        "owasp": ["A01:2021 - Broken Access Control", "A10:2021 - SSRF (relacionado)"],
        "attck": ["T1566"],  # Phishing
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },
    "SRV-011": {
        "cwe": ["CWE-20"],
        "vulnerability": "Uso direto de parâmetros de entrada",
        "risk": "Abre superfícies para injeções e lógica insegura.",
        "remediation": "Validação/normalização; tipagem forte; DTOs/binders seguros.",
        "mitigation": "Bibliotecas de validação e esquemas declarativos.",
        "explanation": "Dados não validados podem manipular a lógica ou alcançar sinks perigosos.",
        "stride": ["Tampering"],
        "attack_types": ["Injection Surface", "Input Validation Failure"],
        "owasp": ["A01:2021 - Broken Access Control", "A03:2021 - Injection"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },

    # Criptografia/algoritmos
    "SRV-020": {
        "cwe": ["CWE-328", "CWE-327"],
        "vulnerability": "Hash/algoritmo criptográfico fraco (MD5/SHA1)",
        "risk": "Colisões e cracking; forja de assinaturas.",
        "remediation": "Usar SHA-256/512; para senhas use bcrypt/Argon2 com sal/custo.",
        "mitigation": "Rotacionar credenciais; re-hash seguro; reforçar políticas de senha.",
        "explanation": "Algoritmos fracos não resistem a ataques de colisão e força bruta modernos.",
        "stride": ["Repudiation", "Information Disclosure"],
        "attack_types": ["Crypto Weakness", "Password Cracking"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    "SRV-021": {
        "cwe": ["CWE-327"],
        "vulnerability": "Base64 usado como 'criptografia'",
        "risk": "Dados sensíveis reversíveis; exposição.",
        "remediation": "Criptografia autenticada (AES-GCM/ChaCha20-Poly1305).",
        "mitigation": "Gestão de chaves; KMS/HSM; rotação periódica.",
        "explanation": "Base64 é apenas codificação; não há sigilo nem integridade.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Crypto Weakness"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    "SRV-022": {
        "cwe": ["CWE-327", "CWE-330"],
        "vulnerability": "Pseudo-criptografia artesanal",
        "risk": "Proteção ilusória; reversão simples.",
        "remediation": "Usar bibliotecas maduras e padrões reconhecidos.",
        "mitigation": "Threat modeling e revisão criptográfica.",
        "explanation": "Operações ad hoc não fornecem confidencialidade/integridade robusta.",
        "stride": ["Information Disclosure", "Repudiation"],
        "attack_types": ["Crypto Weakness"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
    },

    # Injeções / Execução
    "SRV-030": {
        "cwe": ["CWE-89"],
        "vulnerability": "SQL Injection",
        "risk": "Exfiltração/alteração de dados e até RCE via features do SGBD.",
        "remediation": "Parametrização/ORM, validação e menor privilégio no DB.",
        "mitigation": "WAF, escaping contextual e proteção por roles no DB.",
        "explanation": "Entrada do usuário chega a consultas sem parametrização, controlando o SQL final.",
        "stride": ["Tampering", "Information Disclosure", "Elevation of Privilege"],
        "attack_types": ["Injection/SQLi"],
        "owasp": ["A03:2021 - Injection"],
        "attck": ["T1190"],  # Exploit Public-Facing App (genérico)
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    "SRV-031": {
        "cwe": ["CWE-94"],
        "vulnerability": "Code Injection via eval/exec",
        "risk": "Execução arbitrária e tomada do host.",
        "remediation": "Remover eval/exec; whitelists/parsers; sandbox.",
        "mitigation": "Assinatura de código; isolamento/least privilege.",
        "explanation": "Interpretadores executam cadeias manipuláveis como código.",
        "stride": ["Elevation of Privilege", "Tampering"],
        "attack_types": ["RCE", "Code Injection"],
        "owasp": ["A03:2021 - Injection"],
        "attck": ["T1059"],  # Command & Scripting
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    "SRV-032": {
        "cwe": ["CWE-78"],
        "vulnerability": "Command Injection (SO)",
        "risk": "Execução de comandos arbitrários e exfiltração.",
        "remediation": "APIs com lista de args (sem shell); validar/escapar entradas.",
        "mitigation": "AppArmor/SELinux e isolamento de processo.",
        "explanation": "Concatenação perigosa permite injetar argumentos/comandos no shell.",
        "stride": ["Elevation of Privilege", "Tampering"],
        "attack_types": ["RCE", "OS Command Injection"],
        "owasp": ["A03:2021 - Injection"],
        "attck": ["T1059"],
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    "SRV-033": {
        "cwe": ["CWE-78"],
        "vulnerability": "Construção de comandos por concatenação",
        "risk": "Porta de entrada para injeção e RCE.",
        "remediation": "Executar por lista de args; nunca concatenar.",
        "mitigation": "Validação rigorosa de entrada; dropar shell.",
        "explanation": "Strings concatenadas com dados de usuário geram comandos controláveis.",
        "stride": ["Tampering", "Elevation of Privilege"],
        "attack_types": ["RCE", "OS Command Injection"],
        "owasp": ["A03:2021 - Injection"],
        "attck": ["T1059"],
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },

    # Entrada/arquivos/rede
    "SRV-040": {
        "cwe": ["CWE-22"],
        "vulnerability": "Acesso a arquivo sem validação (Path Traversal potencial)",
        "risk": "Leitura de arquivos sensíveis; disclosure de segredos.",
        "remediation": "Normalizar e restringir paths (allowlist).",
        "mitigation": "Sandboxes e isolamentos de FS; permissões mínimas.",
        "explanation": "Parâmetros de caminho podem escapar do diretório esperado.",
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "attack_types": ["Path Traversal"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    "SRV-041": {
        "cwe": ["CWE-434"],
        "vulnerability": "Upload sem restrições (tipo/validação)",
        "risk": "Web shells e execução remota.",
        "remediation": "Validar MIME/assinatura; armazenar fora do webroot.",
        "mitigation": "Bloquear execução em diretórios de upload; nomes aleatórios; AV.",
        "explanation": "Arquivos maliciosos podem ser carregados e executados no servidor.",
        "stride": ["Elevation of Privilege", "Tampering"],
        "attack_types": ["Unrestricted File Upload", "Web Shell"],
        "owasp": ["A01:2021 - Broken Access Control", "A05:2021 - Security Misconfiguration"],
        "attck": ["T1505.003"],  # Web Shell
        "references": ["https://cwe.mitre.org/data/definitions/434.html"],
    },
    "SRV-042": {
        "cwe": ["CWE-548"],
        "vulnerability": "Listagem de diretório",
        "risk": "Revela estrutura/artefatos para reconhecimento.",
        "remediation": "Desabilitar autoindex; bloquear listagens.",
        "mitigation": "Config hardening do servidor web.",
        "explanation": "Enumerar diretórios facilita descoberta de endpoints e artefatos.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Reconnaissance Aid"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/548.html"],
    },

    # HTTP/Headers/Sessão
    "SRV-050": {
        "cwe": ["CWE-614"],
        "vulnerability": "Cookie de sessão sem Secure",
        "risk": "Roubo de sessão via sniffing (HTTP não criptografado).",
        "remediation": "Definir Secure/HttpOnly/SameSite; forçar HTTPS.",
        "mitigation": "HSTS e TLS em todo o tráfego.",
        "explanation": "Sessões podem ser capturadas em redes comprometidas.",
        "stride": ["Information Disclosure", "Spoofing"],
        "attack_types": ["Session Hijacking"],
        "owasp": ["A07:2021 - Identification and Authentication Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },
    "SRV-051": {
        "cwe": ["CWE-693"],
        "vulnerability": "Headers de segurança ausentes (menção)",
        "risk": "Aumento de superfície para XSS/clickjacking.",
        "remediation": "Aplicar CSP, XFO, X-Content-Type-Options, HSTS.",
        "mitigation": "Políticas de cabeçalhos padrão e testes E2E.",
        "explanation": "Sem headers, o navegador não aplica proteções nativas.",
        "stride": ["Information Disclosure", "Tampering"],
        "attack_types": ["Browser Exploitation Surface"],
        "owasp": ["A05:2021 - Security Misconfiguration"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/693.html"],
    },
    "SRV-052": {
        "cwe": ["CWE-295"],
        "vulnerability": "Verificação TLS desativada",
        "risk": "MITM, conexão com endpoints maliciosos.",
        "remediation": "Sempre validar certificados; pinning quando aplicável.",
        "mitigation": "Impedir flags de bypass em builds de produção.",
        "explanation": "Desabilitar validação remove garantias de autenticidade do servidor.",
        "stride": ["Spoofing", "Information Disclosure"],
        "attack_types": ["Man-in-the-Middle"],
        "owasp": ["A05:2021 - Security Misconfiguration"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },

    # XSS
    "SRV-060": {
        "cwe": ["CWE-79"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "risk": "Roubo de sessão, defacement, pivot para outras contas.",
        "remediation": "Escapar por contexto, CSP, sanitização/templating seguro.",
        "mitigation": "Bibliotecas de template seguras e validação rigorosa.",
        "explanation": "Dados do usuário injetam script no cliente, executado no contexto do site.",
        "stride": ["Elevation of Privilege", "Information Disclosure"],
        "attack_types": ["XSS"],
        "owasp": ["A03:2021 - Injection"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },

    # Qualidade/Práticas
    "SRV-070": {
        "cwe": ["CWE-703"],
        "vulnerability": "Tratamento genérico de exceções",
        "risk": "Mascaramento de falhas; possível disclosure via stack traces.",
        "remediation": "Capturar exceções específicas; logs sem segredos; fail-safe.",
        "mitigation": "Padrões de erro e observabilidade segura.",
        "explanation": "Tratamento amplo dificulta resposta segura e facilita mau estado.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Error Handling Weakness"],
        "owasp": ["A09:2021 - Security Logging and Monitoring Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/703.html"],
    },
    "SRV-071": {
        "cwe": ["CWE-215"],
        "vulnerability": "Modo debug/log verboso em produção",
        "risk": "Exposição de dados sensíveis via logs/traces.",
        "remediation": "Desabilitar debug; ajustar níveis/mascaramento.",
        "mitigation": "Controles de acesso a logs e retenção mínima.",
        "explanation": "Ambientes de produção não devem expor detalhes internos.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Information Leak"],
        "owasp": ["A09:2021 - Security Logging and Monitoring Failures"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/215.html"],
    },
    "SRV-072": {
        "cwe": ["CWE-200", "CWE-615"],
        "vulnerability": "Segredo/senha em comentários",
        "risk": "Descoberta acidental e abuso por terceiros.",
        "remediation": "Remover; hooks pre-commit; scans de segredos.",
        "mitigation": "Rotação de credenciais; DLP em repositórios.",
        "explanation": "Comentários são rastreados por varredores e bots.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Credential Exposure"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "attck": ["T1552"],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # Caminhos sensíveis
    "SRV-080": {
        "cwe": ["CWE-200"],
        "vulnerability": "Menção a paths sensíveis/endpoints administrativos",
        "risk": "Facilita reconhecimento e enumeração de superfície.",
        "remediation": "Proteger com auth/ACL; não expor paths internos ao cliente.",
        "mitigation": "Rate limit e monitoramento de enumeração.",
        "explanation": "Pistas de estrutura interna aceleram recon e exploração dirigida.",
        "stride": ["Information Disclosure"],
        "attack_types": ["Reconnaissance Aid"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },

    # Rotas (heurística Python)
    "SRV-090": {
        "cwe": ["CWE-306"],
        "vulnerability": "Rota possivelmente sem autenticação obrigatória",
        "risk": "Acesso não autenticado a funções críticas.",
        "remediation": "Decorators/filtros de autenticação/autorização; testes de acesso.",
        "mitigation": "Políticas de autorização centralizadas; ABAC/RBAC.",
        "explanation": "Ausência de verificação de identidade/role permite abuso de endpoints.",
        "stride": ["Elevation of Privilege"],
        "attack_types": ["Broken Access Control"],
        "owasp": ["A01:2021 - Broken Access Control"],
        "attck": [],
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
    },
}

# Pré-compila regex
for r in RULES:
    if r.get("re"):
        r["rx"] = re.compile(r["re"], re.IGNORECASE)

def is_text_file(path: str, limit: int = 8192) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(limit)
        if b"\x00" in chunk:
            return False
        return True
    except Exception:
        return False

def should_skip(path: str, skip_dirs: Iterable[str]) -> bool:
    parts = set(os.path.normpath(path).split(os.sep))
    return any(d in parts for d in skip_dirs)

def truncate(s: str, n: int = 300) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"

def scan_file(path: str, rules: List[Dict], max_bytes: int) -> List[Dict]:
    findings: List[Dict] = []
    if not is_text_file(path):
        return findings
    try:
        if os.path.getsize(path) > max_bytes:
            return findings
    except OSError:
        return findings

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except Exception as e:
        return [{
            "rule_id": "SRV-000",
            "title": "Erro de leitura",
            "severity": "INFO",
            "file": path,
            "line": 1,
            "message": f"Não foi possível analisar o arquivo: {e}",
            "snippet": "",
            "vulnerability": "",
            "risk": "",
            "remediation": "",
            "mitigation": "",
            "explanation": "",
            "stride": [],
            "attack_types": [],
            "owasp": [],
            "attck": [],
            "cwe": [],
            "references": [],
        }]

    for idx, line in enumerate(lines, start=1):
        l = line.rstrip("\n")
        for rr in rules:
            rx = rr.get("rx")
            if rx and rx.search(line):
                meta = RULE_META.get(rr["id"], {})
                findings.append({
                    "rule_id": rr["id"],
                    "title": rr["name"],
                    "severity": rr["sev"],
                    "file": path,
                    "line": idx,
                    "message": f"Possível ocorrência: {rr['name']}",
                    "snippet": truncate(l),

                    # Campos existentes
                    "vulnerability": meta.get("vulnerability", rr["name"]),
                    "risk": meta.get("risk", "Risco potencial não especificado."),
                    "remediation": meta.get("remediation", "Revise a implementação conforme boas práticas de segurança."),
                    "cwe": meta.get("cwe", []),
                    "references": meta.get("references", []),

                    # Campos novos
                    "mitigation": meta.get("mitigation", meta.get("remediation", "")),
                    "explanation": meta.get("explanation", ""),
                    "stride": meta.get("stride", []),
                    "attack_types": meta.get("attack_types", []),
                    "owasp": meta.get("owasp", []),
                    "attck": meta.get("attck", []),
                })

    # Heurística: rotas sem autenticação (python)
    if path.endswith(".py"):
        findings.extend(detect_unauthenticated_routes(lines, path))

    return dedup(findings)

def dedup(findings: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f["file"], f["line"], f["rule_id"], f.get("snippet", ""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

def detect_unauthenticated_routes(lines: List[str], path: str) -> List[Dict]:
    out: List[Dict] = []
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("def ") and "(" in s and s.endswith(":"):
            window = lines[max(0, i-3):i]
            decorators = [w.strip() for w in window if w.strip().startswith("@")]
            protected = any(re.search(r"@(login_required|jwt_required|auth(\.|_)required)", d) for d in decorators)
            if not protected:
                meta = RULE_META.get("SRV-090", {})
                out.append({
                    "rule_id": "SRV-090",
                    "title": "rota sem autenticação (heurístico)",
                    "severity": "HIGH",
                    "file": path,
                    "line": i+1,
                    "message": "Função de rota possivelmente sem decorator de autenticação (@login_required/@jwt_required/@auth_required).",
                    "snippet": truncate(s),

                    "vulnerability": meta.get("vulnerability", "Rota sem autenticação"),
                    "risk": meta.get("risk", "Acesso não autenticado a funções críticas."),
                    "remediation": meta.get("remediation", "Aplicar decorators/filtros de autenticação/autorização nas rotas."),
                    "mitigation": meta.get("mitigation", meta.get("remediation", "")),
                    "explanation": meta.get("explanation", ""),
                    "stride": meta.get("stride", []),
                    "attack_types": meta.get("attack_types", []),
                    "owasp": meta.get("owasp", []),
                    "attck": meta.get("attck", []),
                    "cwe": meta.get("cwe", []),
                    "references": meta.get("references", []),
                })
    return out

def walk_files(root: str, exts: Iterable[str], skip_dirs: Iterable[str]) -> Iterable[str]:
    exts = tuple(exts)
    skip_dirs = set(skip_dirs)
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            full = os.path.join(r, f)
            if should_skip(full, skip_dirs):
                continue
            if f.lower().endswith(exts):
                yield full

def summarize(findings: List[Dict]) -> Dict[str, int]:
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        s = f["severity"]
        counts[s] = counts.get(s, 0) + 1
    return counts

def to_json(findings: List[Dict]) -> Dict:
    return {"results": findings}

def _md_list(items: List[str]) -> str:
    return "\n".join(f"- {x}" for x in items) if items else "- (não informado)"

def _sarif_help_markdown(meta: Dict) -> str:
    vuln = meta.get("vulnerability", "")
    risk = meta.get("risk", "")
    rem  = meta.get("remediation", "")
    mit  = meta.get("mitigation", rem)
    exp  = meta.get("explanation", "")
    refs = meta.get("references", [])
    stride = meta.get("stride", [])
    attack_types = meta.get("attack_types", [])
    owasp = meta.get("owasp", [])
    attck = meta.get("attck", [])

    parts = []
    if vuln: parts.append(f"**Vulnerabilidade**: {vuln}")
    if exp:  parts.append(f"\n**Como é explorado**: {exp}")
    if risk: parts.append(f"\n**Risco**: {risk}")
    if mit:  parts.append(f"\n**Mitigação**: {mit}")

    parts.append("\n**Modelos e referências**:")
    parts.append(f"- **STRIDE**: {', '.join(stride) if stride else '(n/d)'}")
    parts.append(f"- **Tipo(s) de ataque**:\n{_md_list(attack_types)}")
    parts.append(f"- **OWASP**: {', '.join(owasp) if owasp else '(n/d)'}")
    parts.append(f"- **MITRE ATT&CK**: {', '.join(attck) if attck else '(n/d)'}")
    if refs:
        parts.append("\n**Referências adicionais:**\n" + "\n".join(f"- {u}" for u in refs))
    return "\n".join(parts)

def to_sarif(findings: List[Dict]) -> Dict:
    # Regras únicas com ajuda/descrição e propriedades
    rules_map: Dict[str, Dict] = {}
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_map:
            meta = RULE_META.get(rid, {})
            rules_map[rid] = {
                "id": rid,
                "name": f.get("title", rid),
                "shortDescription": {"text": f.get("title", rid)},
                "fullDescription": {"text": f.get("vulnerability", f.get("message", f.get("title", rid)))},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f["severity"], "note")},
                "help": {"text": _sarif_help_markdown(meta), "markdown": _sarif_help_markdown(meta)},
                "properties": {
                    "problem.severity": f.get("severity", "INFO"),
                    "tags": [*meta.get("cwe", []), "security", "custom-review"],
                    "stride": meta.get("stride", []),
                    "attack_types": meta.get("attack_types", []),
                    "owasp": meta.get("owasp", []),
                    "attck": meta.get("attck", []),
                },
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule_id"],
            "level": SEV_TO_SARIF.get(f["severity"], "note"),
            "message": {"text": f.get("message", f.get("title", "Finding"))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]}
                }
            }],
            "properties": {
                "cwe": f.get("cwe", []),
                "vulnerability": f.get("vulnerability", ""),
                "risk": f.get("risk", ""),
                "remediation": f.get("remediation", ""),
                "mitigation": f.get("mitigation", ""),
                "explanation": f.get("explanation", ""),
                "stride": f.get("stride", []),
                "attack_types": f.get("attack_types", []),
                "owasp": f.get("owasp", []),
                "attck": f.get("attck", []),
                "snippet": f.get("snippet", ""),
                "references": f.get("references", []),
            }
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Custom Security Review (enhanced + STRIDE)",
                    "informationUri": "https://example.local/custom-security-review",
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
    return sarif

def write_csv(findings: List[Dict], csv_path: str) -> None:
    """CSV com colunas estendidas (STRIDE, Attack Types, Explanation, Mitigation, OWASP, ATT&CK)."""
    fieldnames = [
        "Rule ID", "Severity", "File", "Line", "Message", "Snippet",
        "Vulnerability", "Risk", "Remediation", "Mitigation", "Explanation",
        "STRIDE", "Attack Types", "OWASP", "ATT&CK", "CWE", "References"
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for it in findings:
            w.writerow({
                "Rule ID": it.get("rule_id", ""),
                "Severity": it.get("severity", ""),
                "File": it.get("file", ""),
                "Line": it.get("line", ""),
                "Message": it.get("message", ""),
                "Snippet": it.get("snippet", ""),

                "Vulnerability": it.get("vulnerability", ""),
                "Risk": it.get("risk", ""),
                "Remediation": it.get("remediation", ""),
                "Mitigation": it.get("mitigation", ""),
                "Explanation": it.get("explanation", ""),

                "STRIDE": ",".join(it.get("stride", [])),
                "Attack Types": ",".join(it.get("attack_types", [])),
                "OWASP": ",".join(it.get("owasp", [])),
                "ATT&CK": ",".join(it.get("attck", [])),

                "CWE": ",".join(it.get("cwe", [])),
                "References": ",".join(it.get("references", [])),
            })

def main():
    ap = argparse.ArgumentParser("custom_security_review_enhanced_stride")
    ap.add_argument("--root", default=".", help="Diretório raiz do projeto")
    ap.add_argument("--json-out", default="custom-review.json", help="Arquivo JSON de saída")
    ap.add_argument("--sarif-out", default="custom-review.sarif", help="Arquivo SARIF 2.1.0 de saída")
    ap.add_argument("--csv-out", default=None, help="Arquivo CSV de saída (opcional)")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Tamanho máximo por arquivo")
    ap.add_argument("--include-extensions", default=",".join(DEFAULT_EXTS), help="Extensões que serão analisadas (csv)")
    ap.add_argument("--exclude-dirs", default=",".join(sorted(DEFAULT_SKIP_DIRS)), help="Pastas a ignorar (csv)")
    ap.add_argument("--fail-on", choices=SEV_ORDER, help="Falha (exit 1) se houver achados >= severidade informada")
    args = ap.parse_args()

    max_bytes = int(args.max_bytes)
    exts = [e.strip().lower() for e in args.include_extensions.split(",") if e.strip()]
    skip_dirs = set([d.strip() for d in args.exclude_dirs.split(",") if d.strip()])

    all_findings: List[Dict] = []
    for p in walk_files(args.root, exts, skip_dirs):
        all_findings.extend(scan_file(p, RULES, max_bytes))
    all_findings = dedup(all_findings)

    with open(args.json_out, "w", encoding="utf-8") as fj:
        json.dump(to_json(all_findings), fj, ensure_ascii=False, indent=2)

    with open(args.sarif_out, "w", encoding="utf-8") as fsr:
        json.dump(to_sarif(all_findings), fsr, ensure_ascii=False, indent=2)

    if args.csv_out:
        write_csv(all_findings, args.csv_out)

    counts = summarize(all_findings)
    total = sum(counts.values())
    print(f"[custom-review] encontrados {total} achados -> {counts}")

    if args.fail_on:
        if any(sev_gte(s, args.fail_on) and c > 0 for s, c in counts.items()):
            sys.exit(1)

if __name__ == "__main__":
    main()
