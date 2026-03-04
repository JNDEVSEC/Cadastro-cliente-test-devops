#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom Security Review (enhanced, text-aware)
- Inclui metadados por achado (vulnerabilidade, risco, correção, CWE, referências).
- Suporta varredura de arquivos de texto comuns: Dockerfile (sem extensão), .yaml/.yml, .env, .ini, .conf, .cfg, .properties, etc.
- Adiciona heurísticas específicas para Dockerfile e YAML/Kubernetes/Compose.
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
# Extensões padrão + formatos de texto de config
DEFAULT_EXTS = [
    ".py", ".js", ".php", ".java", ".ts", ".jsx", ".tsx",
    ".yaml", ".yml", ".env", ".ini", ".conf", ".cfg", ".properties",
]

# Nomes de arquivos considerados texto mesmo sem extensão (ex.: Dockerfile)
TEXT_ONLY_BASENAMES = {"dockerfile", "Dockerfile"}

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

# Metadados por regra
RULE_META: Dict[str, Dict] = {
    "SRV-001": {"cwe": ["CWE-798"], "vulnerability": "Credenciais/API Keys hardcoded expostas no código", "risk": "Acesso não autorizado e takeover.", "remediation": "Remover do código e usar secret manager; rotacionar chaves.", "references": ["https://cwe.mitre.org/data/definitions/798.html"]},
    "SRV-002": {"cwe": ["CWE-321"], "vulnerability": "Chave privada/certificado no repositório", "risk": "Impersonation/MITM.", "remediation": "Remover, guardar em vault/KMS e rotacionar imediatamente.", "references": ["https://cwe.mitre.org/data/definitions/321.html"]},
    "SRV-003": {"cwe": ["CWE-798", "CWE-312"], "vulnerability": "Atribuição de segredo sensível", "risk": "Vazamento via VCS/logs.", "remediation": "Usar variáveis/env e secret manager; revisar histórico.", "references": ["https://cwe.mitre.org/data/definitions/312.html"]},
    "SRV-004": {"cwe": ["CWE-200"], "vulnerability": "Segredo vazio/nulo", "risk": "Fallback inseguro/exposição.", "remediation": "Validar obrigatoriedade; falhar build se ausente.", "references": ["https://cwe.mitre.org/data/definitions/200.html"]},
    "SRV-010": {"cwe": ["CWE-601"], "vulnerability": "Open Redirect", "risk": "Phishing/bypass.", "remediation": "Allowlist de destinos; normalização.", "references": ["https://cwe.mitre.org/data/definitions/601.html"]},
    "SRV-011": {"cwe": ["CWE-20"], "vulnerability": "Uso direto de parâmetros", "risk": "Injeções e lógica insegura.", "remediation": "Validação/normalização tipada.", "references": ["https://cwe.mitre.org/data/definitions/20.html"]},
    "SRV-020": {"cwe": ["CWE-328", "CWE-327"], "vulnerability": "Algoritmo criptográfico fraco", "risk": "Colisões/cracking.", "remediation": "SHA-256/512, bcrypt/Argon2, sal/custo.", "references": ["https://cwe.mitre.org/data/definitions/327.html"]},
    "SRV-021": {"cwe": ["CWE-327"], "vulnerability": "Base64 como 'cripto'", "risk": "Reversão trivial.", "remediation": "Criptografia autenticada (AES-GCM).", "references": ["https://cwe.mitre.org/data/definitions/327.html"]},
    "SRV-022": {"cwe": ["CWE-327", "CWE-330"], "vulnerability": "'Homebrew crypto' aritmética", "risk": "Proteção ilusória.", "remediation": "Usar libs padrão.", "references": ["https://cwe.mitre.org/data/definitions/330.html"]},
    "SRV-030": {"cwe": ["CWE-89"], "vulnerability": "SQL Injection", "risk": "Exfiltração/RCE.", "remediation": "Parametrização/ORM e validação.", "references": ["https://cwe.mitre.org/data/definitions/89.html"]},
    "SRV-031": {"cwe": ["CWE-94"], "vulnerability": "Code Injection via eval/exec", "risk": "Execução arbitrária.", "remediation": "Remover eval/exec; whitelists/parsers.", "references": ["https://cwe.mitre.org/data/definitions/94.html"]},
    "SRV-032": {"cwe": ["CWE-78"], "vulnerability": "Command Injection (SO)", "risk": "Execução de comandos.", "remediation": "APIs seguras (args list), sem shell.", "references": ["https://cwe.mitre.org/data/definitions/78.html"]},
    "SRV-033": {"cwe": ["CWE-78"], "vulnerability": "Concatenação de comandos", "risk": "Injeção facilitada.", "remediation": "Construir lista de args; sanitizar dados.", "references": ["https://cwe.mitre.org/data/definitions/78.html"]},
    "SRV-040": {"cwe": ["CWE-22"], "vulnerability": "Path Traversal potencial", "risk": "Leitura de arquivos sensíveis.", "remediation": "Normalizar/restringir paths.", "references": ["https://cwe.mitre.org/data/definitions/22.html"]},
    "SRV-041": {"cwe": ["CWE-434"], "vulnerability": "Upload sem restrições", "risk": "Web shells/RCE.", "remediation": "Validar MIME/assinatura; armazenar fora do webroot.", "references": ["https://cwe.mitre.org/data/definitions/434.html"]},
    "SRV-042": {"cwe": ["CWE-548"], "vulnerability": "Listagem de diretório", "risk": "Exposição de estrutura.", "remediation": "Desabilitar autoindex.", "references": ["https://cwe.mitre.org/data/definitions/548.html"]},
    "SRV-050": {"cwe": ["CWE-614"], "vulnerability": "Cookie sem Secure", "risk": "Roubo de sessão.", "remediation": "Secure/HttpOnly/SameSite e HTTPS.", "references": ["https://cwe.mitre.org/data/definitions/614.html"]},
    "SRV-051": {"cwe": ["CWE-693"], "vulnerability": "Headers de segurança ausentes", "risk": "Superfície p/ XSS/clickjacking.", "remediation": "CSP, XFO, X-Content-Type-Options, HSTS.", "references": ["https://cwe.mitre.org/data/definitions/693.html"]},
    "SRV-052": {"cwe": ["CWE-295"], "vulnerability": "TLS sem verificação", "risk": "MITM/exfiltração.", "remediation": "Sempre validar cert; sem verify=False.", "references": ["https://cwe.mitre.org/data/definitions/295.html"]},
    "SRV-060": {"cwe": ["CWE-79"], "vulnerability": "XSS", "risk": "Roubo de sessão.", "remediation": "Escapar por contexto, CSP, sanitização.", "references": ["https://cwe.mitre.org/data/definitions/79.html"]},
    "SRV-070": {"cwe": ["CWE-703"], "vulnerability": "Exceção genérica", "risk": "Oculta falhas e condições inseguras.", "remediation": "Capturar tipos específicos; fail-safe.", "references": ["https://cwe.mitre.org/data/definitions/703.html"]},
    "SRV-071": {"cwe": ["CWE-215"], "vulnerability": "Debug/log verboso em prod", "risk": "Vazamento via logs/traces.", "remediation": "Desabilitar debug; scrubbing.", "references": ["https://cwe.mitre.org/data/definitions/215.html"]},
    "SRV-072": {"cwe": ["CWE-200", "CWE-615"], "vulnerability": "Segredo em comentários", "risk": "Descoberta acidental.", "remediation": "Remover; hooks pre-commit; scan de segredos.", "references": ["https://cwe.mitre.org/data/definitions/200.html"]},
    "SRV-080": {"cwe": ["CWE-200"], "vulnerability": "Paths sensíveis/adm expostos", "risk": "Facilita enumeração.", "remediation": "Proteger com auth/ACL; não logar paths internos.", "references": ["https://cwe.mitre.org/data/definitions/200.html"]},
    "SRV-090": {"cwe": ["CWE-306"], "vulnerability": "Rota possivelmente sem autenticação", "risk": "Acesso não autenticado.", "remediation": "Aplicar decorators/filtros de auth.", "references": ["https://cwe.mitre.org/data/definitions/306.html"]},
}

# IDs especiais para regras "de arquivo" (sem linha específica)
FILE_RULES_META = {
    "DF-001": {"cwe": ["CWE-16"], "vulnerability": "Dockerfile sem HEALTHCHECK", "risk": "Menor detecção de falhas em runtime e health probes.", "remediation": "Adicionar instrução HEALTHCHECK adequada no Dockerfile.", "references": ["https://docs.docker.com/reference/dockerfile/#healthcheck"]},
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
            "cwe": [],
            "references": [],
        }]

    # Regras genéricas por linha
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

    # Heurísticas específicas por tipo de arquivo
    base = os.path.basename(path)
    lower_base = base.lower()

    # 1) Dockerfile (nome sem extensão)
    if lower_base in {"dockerfile"} or lower_base.startswith("dockerfile"):
        findings.extend(scan_dockerfile_specific(path, lines))

    # 2) YAML (Kubernetes/Compose)
    if lower_base.endswith(('.yaml', '.yml')) or path.lower().endswith(('.yaml', '.yml')):
        findings.extend(scan_yaml_specific(path, lines))

    # Heurística: rotas sem autenticação (python)
    if path.endswith(".py"):
        findings.extend(detect_unauthenticated_routes(lines, path))

    return dedup(findings)


def scan_dockerfile_specific(path: str, lines: List[str]) -> List[Dict]:
    out: List[Dict] = []
    content = "\n".join(lines)

    # DF-001: Sem HEALTHCHECK
    if not re.search(r"^\s*HEALTHCHECK\b", content, re.IGNORECASE | re.MULTILINE):
        meta = FILE_RULES_META["DF-001"]
        out.append({
            "rule_id": "DF-001",
            "title": "Dockerfile sem HEALTHCHECK",
            "severity": "LOW",
            "file": path,
            "line": 1,
            "message": "Arquivo Dockerfile não contém instrução HEALTHCHECK.",
            "snippet": "(arquivo)",
            "vulnerability": meta["vulnerability"],
            "risk": meta["risk"],
            "remediation": meta["remediation"],
            "cwe": meta["cwe"],
            "references": meta["references"],
        })

    # Regras inline específicas comuns
    docker_inline_rules = [
        (r"^\s*FROM\s+.+:latest\b", "HIGH", "Uso de tag 'latest'", "CWE-16", "Imprevisibilidade na base da imagem.", "Fixar versão/tag imutável (ex.: :3.12).", ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"] ),
        (r"^\s*USER\s+root\b", "MEDIUM", "Execução como root", "CWE-250", "Amplia impacto de exploração.", "Criar e usar usuário não privilegiado (USER appuser).", ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"]),
        (r"^\s*RUN\s+.*(curl|wget).*(\||;).*sh\b", "HIGH", "Execução de script remoto sem verificação", "CWE-494", "Injeção de conteúdo remoto sem integridade.", "Baixar com checksum/assinatura e não pipe para shell diretamente.", ["https://cwe.mitre.org/data/definitions/494.html"]) ,
        (r"^\s*RUN\s+.*chmod\s+777\b", "MEDIUM", "Permissões excessivas (chmod 777)", "CWE-732", "Amplia superfície e abuso de arquivos.", "Restringir permissões mínimas necessárias.", ["https://cwe.mitre.org/data/definitions/732.html"]) ,
        (r"^\s*ADD\s+https?://", "MEDIUM", "ADD de URL remota", "CWE-494", "Download implícito sem verificação.", "Prefira curl/wget com verificação e COPY para arquivos locais.", ["https://docs.docker.com/reference/dockerfile/#add"]) ,
        (r"^\s*ENV\s+.*(TOKEN|PASSWORD|API_KEY|SECRET|ACCESS_KEY)\s*=\s*\S+", "HIGH", "Segredo em ENV", "CWE-798", "Vazamento de segredo em imagem/camadas.", "Usar secrets no build/args + secret manager; evitar persistir no layer.", ["https://cwe.mitre.org/data/definitions/798.html"]) ,
    ]

    for idx, line in enumerate(lines, start=1):
        for pattern, sev, title, cwe, risk, rem, refs in docker_inline_rules:
            if re.search(pattern, line, re.IGNORECASE):
                out.append({
                    "rule_id": "DF-ILINE",
                    "title": title,
                    "severity": sev,
                    "file": path,
                    "line": idx,
                    "message": f"Possível ocorrência: {title}",
                    "snippet": truncate(line.strip()),
                    "vulnerability": title,
                    "risk": risk,
                    "remediation": rem,
                    "cwe": [cwe],
                    "references": refs,
                })
    return out


def scan_yaml_specific(path: str, lines: List[str]) -> List[Dict]:
    out: List[Dict] = []
    yaml_inline_rules = [
        (r"\bprivileged:\s*true\b", "HIGH", "Container privilegiado", "CWE-250", "Escala privilégios dentro do host.", "Evitar privileged; usar capabilities estritamente necessárias.", ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"] ),
        (r"\brunAsUser:\s*0\b", "HIGH", "Execução como root (K8s)", "CWE-250", "Root no container amplia impacto.", "Executar como UID não privilegiado e setar runAsNonRoot: true.", ["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"] ),
        (r"\ballowPrivilegeEscalation:\s*true\b", "HIGH", "Permite escalonamento de privilégio", "CWE-250", "Aumenta superfície de abuso.", "Definir allowPrivilegeEscalation: false.", ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"] ),
        (r"\bhostNetwork:\s*true\b", "MEDIUM", "hostNetwork habilitado", "CWE-668", "Exposição de rede do host.", "Evitar hostNetwork salvo necessidade estrita.", ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"] ),
        (r"\bhostPID:\s*true\b", "MEDIUM", "hostPID habilitado", "CWE-668", "Acesso ao namespace de processos do host.", "Manter isolado; desabilitar hostPID.", ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"] ),
        (r"\bhostIPC:\s*true\b", "MEDIUM", "hostIPC habilitado", "CWE-668", "Acesso ao IPC do host.", "Desabilitar hostIPC.", ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"] ),
        (r"\bimage:\s+\S+:latest\b", "MEDIUM", "Uso de imagem com tag latest", "CWE-16", "Builds não reprodutíveis e drift de segurança.", "Fixar tag/sha digest.", ["https://kubernetes.io/docs/concepts/containers/images/"] ),
        (r"\benv:\s*\n(?:\s*-\s*name:\s*(?:TOKEN|PASSWORD|API_KEY|SECRET|ACCESS_KEY)\s*\n\s*value:\s*\S+)", "HIGH", "Segredo em env (YAML)", "CWE-798", "Vazamento de segredo pelo manifesto.", "Usar Secret/External Secret e referenciar via valueFrom/secretKeyRef.", ["https://kubernetes.io/docs/concepts/configuration/secret/"] ),
    ]

    for idx, line in enumerate(lines, start=1):
        for pattern, sev, title, cwe, risk, rem, refs in yaml_inline_rules:
            if re.search(pattern, "\n".join(lines[max(0, idx-3): idx+3]), re.IGNORECASE | re.MULTILINE):
                out.append({
                    "rule_id": "YAML-ILINE",
                    "title": title,
                    "severity": sev,
                    "file": path,
                    "line": idx,
                    "message": f"Possível ocorrência: {title}",
                    "snippet": truncate(lines[idx-1].strip()),
                    "vulnerability": title,
                    "risk": risk,
                    "remediation": rem,
                    "cwe": [cwe],
                    "references": refs,
                })

    return out


def dedup(findings: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("rule_id"), f.get("title"), f.get("snippet", ""))
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
            base = os.path.basename(full)
            if base in TEXT_ONLY_BASENAMES or base.lower().startswith("dockerfile"):
                yield full
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
            meta = RULE_META.get(rid, FILE_RULES_META.get(rid, {}))
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
                    "name": "Custom Security Review (enhanced, text-aware)",
                    "informationUri": "https://example.local/custom-security-review",
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
    return sarif


def write_csv(findings: List[Dict], csv_path: str) -> None:
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
    ap = argparse.ArgumentParser("custom_security_review_enhanced_text")
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
