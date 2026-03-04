#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom Security Review (enhanced)
- Para cada achado, inclui: vulnerabilidade explorável (descrição), risco e correção sugerida.
- Adiciona metadados (CWE, referências) no JSON e SARIF (help markdown), e colunas extras no CSV.
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
    ".next", ".nuxt", ".yarn", ".pnpm-store", "coverage", "scripts"  # scripts opcional
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

# Metadados por regra: CWE, vulnerabilidade explorável (descrição), risco, correção e referências
RULE_META: Dict[str, Dict] = {
    "SRV-001": {
        "cwe": ["CWE-798"],
        "vulnerability": "Credenciais/API Keys hardcoded expostas no código",
        "risk": "Exposição de segredos permite acesso não autorizado a serviços e dados (account/service takeover).",
        "remediation": "Remover credenciais do código. Usar secret manager/variáveis de ambiente; rotacionar as chaves comprometidas; configurar CI/CD para injetar segredos em runtime.",
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/www-project-top-ten/2017/A3-Sensitive_Data_Exposure"
        ],
    },
    "SRV-002": {
        "cwe": ["CWE-321"],
        "vulnerability": "Chave privada/certificado embutido no repositório",
        "risk": "Permite impersonation, MITM e decriptação/tráfego forjado; comprometimento de infraestrutura.",
        "remediation": "Nunca commit ar chaves/certs. Armazenar em vault; usar certificados dinâmicos/KMS; rotacionar imediatamente o par comprometido.",
        "references": [
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
        ],
    },
    "SRV-003": {
        "cwe": ["CWE-798", "CWE-312"],
        "vulnerability": "Atribuição de segredo sensível em texto plano",
        "risk": "Vazamento acidental via VCS, logs ou pacotes; acesso não autorizado e pivoting.",
        "remediation": "Mover segredos para gestão central (vault), remover do código, usar referências (env/secret manager) e revisão de commits anteriores.",
        "references": ["https://cwe.mitre.org/data/definitions/312.html"],
    },
    "SRV-004": {
        "cwe": ["CWE-200"],
        "vulnerability": "Configuração de segredo vazio/nulo",
        "risk": "Pode resultar em desativação involuntária de controles ou fallback inseguro, expondo dados.",
        "remediation": "Validar obrigatoriedade e formato de segredos; falhar o build/deploy se ausente; usar policy as code.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "SRV-010": {
        "cwe": ["CWE-601"],
        "vulnerability": "Open Redirect",
        "risk": "Phishing/chaining de ataques (roubo de sessão, bypass de filtros).",
        "remediation": "Usar allowlist de domínios/caminhos; validar e normalizar destinos; evitar confiar em parâmetros do usuário.",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
    },
    "SRV-011": {
        "cwe": ["CWE-20"],
        "vulnerability": "Uso direto de parâmetros de entrada",
        "risk": "Superfície para injeções e lógica insegura.",
        "remediation": "Aplicar validação/normalização e tipagem; usar DTOs/binders seguros e validações server-side.",
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
    },
    "SRV-020": {
        "cwe": ["CWE-328", "CWE-327"],
        "vulnerability": "Uso de hash/algoritmo criptográfico fraco (MD5/SHA1/etc.)",
        "risk": "Quebra por colisão, preimage e cracking rápido; permissões de forja de assinaturas.",
        "remediation": "Migrar para algoritmos modernos (SHA-256/512, bcrypt/Argon2 para senhas) com sal/custo apropriado.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html", "https://cwe.mitre.org/data/definitions/328.html"],
    },
    "SRV-021": {
        "cwe": ["CWE-327"],
        "vulnerability": "Uso de Base64 como 'criptografia'",
        "risk": "Reversível sem segredo; exposição de dados sensíveis.",
        "remediation": "Usar criptografia autenticada (AES-GCM/ChaCha20-Poly1305) com gestão de chaves segura.",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    "SRV-022": {
        "cwe": ["CWE-327", "CWE-330"],
        "vulnerability": "Pseudo-criptografia por operação aritmética/concatenada",
        "risk": "Proteção ilusória; fácil engenharia reversa e vazamento.",
        "remediation": "Usar bibliotecas criptográficas padrão; evitar 'homebrew crypto'.",
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
    },
    "SRV-030": {
        "cwe": ["CWE-89"],
        "vulnerability": "SQL Injection",
        "risk": "Exfiltração/modificação de dados, RCE via UDF/stacked queries.",
        "remediation": "Usar queries parametrizadas/ORM, validar entrada, princípio de menor privilégio no DB.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    },
    "SRV-031": {
        "cwe": ["CWE-94"],
        "vulnerability": "Code Injection via eval/exec",
        "risk": "Execução arbitrária de código; takeover do host.",
        "remediation": "Remover eval/exec; usar mapeamentos seguros, whitelists e parsers; sandbox quando necessário.",
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    },
    "SRV-032": {
        "cwe": ["CWE-78"],
        "vulnerability": "Command Injection (SO)",
        "risk": "Execução de comandos arbitrários, exfiltração e persistência.",
        "remediation": "Usar APIs seguras (subprocess com lista/args), evitar shells, validar/escapar entradas.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    "SRV-033": {
        "cwe": ["CWE-78"],
        "vulnerability": "Construção de comandos por concatenação",
        "risk": "Facilita injeção de parâmetros controlados pelo usuário.",
        "remediation": "Construir comandos por lista de argumentos sem shell; sanitizar dados.",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
    },
    "SRV-040": {
        "cwe": ["CWE-22"],
        "vulnerability": "Acesso a arquivo sem validação (Path Traversal)",
        "risk": "Leitura de arquivos sensíveis fora do diretório esperado.",
        "remediation": "Normalizar e restringir caminhos (allowlist), usar APIs que previnem traversal.",
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
    },
    "SRV-041": {
        "cwe": ["CWE-434"],
        "vulnerability": "Upload sem restrições de tipo/validação",
        "risk": "RCE via web shells, sobreposição de arquivos críticos.",
        "remediation": "Validar MIME/assinatura, armazenar fora do webroot, renomear, dimensionar e varrer com AV.",
        "references": ["https://cwe.mitre.org/data/definitions/434.html"],
    },
    "SRV-042": {
        "cwe": ["CWE-548"],
        "vulnerability": "Exposição por listagem de diretório",
        "risk": "Revela estrutura/nomes de arquivos úteis para ataque.",
        "remediation": "Desabilitar autoindex/listagem no servidor; usar index padrão.",
        "references": ["https://cwe.mitre.org/data/definitions/548.html"],
    },
    "SRV-050": {
        "cwe": ["CWE-614"],
        "vulnerability": "Cookie de sessão sem atributo Secure",
        "risk": "Roubo de sessão via sniffing em conexões não criptografadas.",
        "remediation": "Definir Secure/HttpOnly/SameSite; exigir HTTPS em toda a aplicação.",
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
    },
    "SRV-051": {
        "cwe": ["CWE-693"],
        "vulnerability": "Headers de segurança ausentes (menção)",
        "risk": "Aumenta a superfície para XSS, clickjacking, etc.",
        "remediation": "Aplicar CSP, X-Frame-Options, X-Content-Type-Options, HSTS; revisar política.",
        "references": ["https://cwe.mitre.org/data/definitions/693.html"],
    },
    "SRV-052": {
        "cwe": ["CWE-295"],
        "vulnerability": "Verificação de certificado TLS desativada",
        "risk": "MITM, ligação a endpoints maliciosos e exfiltração.",
        "remediation": "Sempre validar certificados; pinning quando aplicável; não usar verify=False.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
    },
    "SRV-060": {
        "cwe": ["CWE-79"],
        "vulnerability": "Cross-Site Scripting (XSS)",
        "risk": "Roubo de sessão, defacement, pivot para outras contas.",
        "remediation": "Escapar/encode por contexto, CSP, sanitização/templating seguro, evitar sinks perigosos.",
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
    },
    "SRV-070": {
        "cwe": ["CWE-703"],
        "vulnerability": "Tratamento genérico de exceções",
        "risk": "Oculta falhas e pode mascarar condições inseguras.",
        "remediation": "Capturar exceções específicas, logar com parcimônia (sem segredos) e falhar de forma segura.",
        "references": ["https://cwe.mitre.org/data/definitions/703.html"],
    },
    "SRV-071": {
        "cwe": ["CWE-215"],
        "vulnerability": "Modo debug/log verboso em produção",
        "risk": "Exfiltração de dados sensíveis via logs/stack traces.",
        "remediation": "Desabilitar debug em prod; ajustar níveis de log e scrubbing de dados.",
        "references": ["https://cwe.mitre.org/data/definitions/215.html"],
    },
    "SRV-072": {
        "cwe": ["CWE-200", "CWE-615"],
        "vulnerability": "Segredo/senha em comentários",
        "risk": "Descoberta acidental por terceiros e varredores.",
        "remediation": "Remover comentários sensíveis, usar pre-commit hooks e scans de segredos na pipeline.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "SRV-080": {
        "cwe": ["CWE-200"],
        "vulnerability": "Menção a paths sensíveis/endpoints administrativos",
        "risk": "Ajuda reconhecimento/enumeração, facilitando exploração.",
        "remediation": "Proteger endpoints com auth/ACL, não expor paths internos em clientes/logs.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "SRV-090": {
        "cwe": ["CWE-306"],
        "vulnerability": "Rota possivelmente sem autenticação obrigatória",
        "risk": "Acesso não autenticado a funções críticas.",
        "remediation": "Aplicar decorators/filtros de autenticação/autorização nas rotas; testes de acesso.",
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
        # Leitura tolerante
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
                    "vulnerability": meta.get("vulnerability", rr["name"]),
                    "risk": meta.get("risk", "Risco potencial não especificado."),
                    "remediation": meta.get("remediation", "Revise a implementação conforme boas práticas de segurança."),
                    "cwe": meta.get("cwe", []),
                    "references": meta.get("references", []),
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


def _sarif_help_markdown(meta: Dict) -> str:
    vuln = meta.get("vulnerability", "")
    risk = meta.get("risk", "")
    rem = meta.get("remediation", "")
    refs = meta.get("references", [])
    md = [f"**Vulnerabilidade**: {vuln}"]
    if risk:
        md.append(f"\n**Risco**: {risk}")
    if rem:
        md.append(f"\n**Correção**: {rem}")
    if refs:
        md.append("\n**Referências:**\n" + "\n".join(f"- {u}" for u in refs))
    return "\n".join(md)


def to_sarif(findings: List[Dict]) -> Dict:
    # Regras únicas com ajuda/descrição
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
                    "name": "Custom Security Review (enhanced)",
                    "informationUri": "https://example.local/custom-security-review",
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
    return sarif


def write_csv(findings: List[Dict], csv_path: str) -> None:
    """Escreve CSV com colunas estendidas."""
    fieldnames = [
        "Rule ID", "Severity", "File", "Line", "Message", "Snippet",
        "Vulnerability", "Risk", "Remediation", "CWE", "References"
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
                "CWE": ",".join(it.get("cwe", [])),
                "References": ",".join(it.get("references", [])),
            })


def main():
    ap = argparse.ArgumentParser("custom_security_review_enhanced")
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

    # Saídas
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
        # Se existir qualquer achado >= fail_on -> exit 1
        if any(sev_gte(s, args.fail_on) and c > 0 for s, c in counts.items()):
            sys.exit(1)

if __name__ == "__main__":
    main()
