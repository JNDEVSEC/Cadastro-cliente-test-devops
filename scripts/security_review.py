#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Iterable

# -----------------------
# Configuração principal
# -----------------------
DEFAULT_EXTS = [".py", ".js", ".php", ".java", ".ts", ".jsx", ".tsx"]
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
    "node_modules", "dist", "build", "out", ".venv", "venv", "__pycache__",
    ".next", ".nuxt", ".yarn", ".pnpm-store", "coverage"
}
MAX_BYTES = 1_000_000  # 1 MB por arquivo

# Severidade -> nível SARIF
SEV_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Severidades ordenadas para gate
SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
def sev_gte(a: str, b: str) -> bool:
    return SEV_ORDER.index(a) >= SEV_ORDER.index(b)

# -----------------------
# Regras (ID, nome, regex, severidade)
# -----------------------
RULES = [
    # Exposição/segredos
    {"id": "SRV-001", "name": "hardcoded api key",
     "re": r"(api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "sev": "CRITICAL"},
    {"id": "SRV-002", "name": "hardcoded certificado/chave privada",
     "re": r"(BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY)", "sev": "CRITICAL"},
    {"id": "SRV-003", "name": "atribuição de chave/segredo sensível",
     "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*['\"][^'\"]{4,}['\"]", "sev": "HIGH"},
    {"id": "SRV-004", "name": "variável sensível vazia/nula",
     "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*([\"']{2}|null)", "sev": "MEDIUM"},

    # Autenticação/autorização
    {"id": "SRV-010", "name": "redirect aberto",
     "re": r"redirect\((request\.GET|url)\)", "sev": "HIGH"},
    {"id": "SRV-011", "name": "uso direto de parâmetro de request",
     "re": r"(request\.GET|request\.POST|\$_GET|\$_POST)", "sev": "LOW"},

    # Criptografia/algoritmos
    {"id": "SRV-020", "name": "uso de algoritmo hash inseguro",
     "re": r"\b(md5|sha1|rot13|crc32)\b\s*\(", "sev": "HIGH"},
    {"id": "SRV-021", "name": "base64 usado como 'criptografia'",
     "re": r"\bbase64\b\s*\(", "sev": "MEDIUM"},
    {"id": "SRV-022", "name": "pseudocriptografia por fórmula",
     "re": r"\b(pass|key|token|secret)\b\s*=\s*\w+\s*[\+\-\*/\^%]\s*\w+", "sev": "MEDIUM"},

    # Injeções / Execução
    {"id": "SRV-030", "name": "SQL injection (heurístico)",
     "re": r"SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*(['\"]?\s*\.\s*\$?\w+\s*\.\s*['\"]?|['\"]\s*\$?\w+\s*['\"])", "sev": "HIGH"},
    {"id": "SRV-031", "name": "uso de eval/exec/new Function",
     "re": r"\b(eval|exec|Function)\s*\(", "sev": "HIGH"},
    {"id": "SRV-032", "name": "execução de comando do SO",
     "re": r"(os\.system|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec)", "sev": "HIGH"},
    {"id": "SRV-033", "name": "comando concatenado (injeção possível)",
     "re": r"(exec\s*\(\s*\".*\"\s*\+\s*\w+)", "sev": "MEDIUM"},

    # Entrada/arquivos/rede
    {"id": "SRV-040", "name": "leitura de arquivo sem validação (path traversal)",
     "re": r"(open\s*\(|fs\.readFile\s*\(|FileReader\s*\()", "sev": "LOW"},
    {"id": "SRV-041", "name": "upload sem restrição",
     "re": r"(move_uploaded_file|file\.upload|req\.files)", "sev": "HIGH"},
    {"id": "SRV-042", "name": "listagem de diretório",
     "re": r"(os\.listdir|readdir\s*\(|\bdir\s*\()", "sev": "LOW"},

    # HTTP/Headers/Sessão
    {"id": "SRV-050", "name": "cookie de sessão sem Secure",
     "re": r"session\.cookie_secure\s*=\s*False", "sev": "HIGH"},
    {"id": "SRV-051", "name": "headers de segurança ausentes (menção)",
     "re": r"(X-Frame-Options|Content-Security-Policy)", "sev": "INFO"},
    {"id": "SRV-052", "name": "verificação de TLS desativada",
     "re": r"(verify\s*=\s*False|ssl\.verify\s*=\s*False)", "sev": "HIGH"},

    # XSS (observação: precisa detectar <script> puro, não &lt;script&gt;)
    {"id": "SRV-060", "name": "XSS (sink perigoso em HTML/JS)",
     "re": r"(document\.write|innerHTML\s*=|<script>|onerror\s*=|onload\s*=|dangerouslySetInnerHTML)", "sev": "HIGH"},

    # Qualidade/Práticas
    {"id": "SRV-070", "name": "tratamento genérico de exceção",
     "re": r"(except\s+Exception\b|catch\s*\(Exception\b)", "sev": "LOW"},
    {"id": "SRV-071", "name": "debug/log verboso em produção",
     "re": r"(debug\s*=\s*True|console\.log|print\s*\()", "sev": "LOW"},
    {"id": "SRV-072", "name": "segredo/senha em comentários",
     "re": r"(#.*senha|//.*password|/\*.*secret)", "sev": "LOW"},

    # Caminhos sensíveis (menção)
    {"id": "SRV-080", "name": "paths sensíveis/administrativos mencionados",
     "re": r"(/admin|/config|/backup|/private|/usuario(s)?|/cliente(s)?|/produto(s)?|/pedidos?|/ordem(s)?|/comiss(o|õ)es?|/acesso|/painel|/controllers|/css|/dist|/img(s)?|/plugins)", "sev": "INFO"},
]

# -----------------------
# Metadados enriquecidos + STRIDE
# -----------------------
# STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
RULE_META: Dict[str, Dict] = {
    "SRV-001": {
        "vulnerability": "Credenciais/API Keys hardcoded presentes no código.",
        "risk": "Exposição de segredos; uso não autorizado de serviços e pivoting.",
        "remediation": "Remover do código; usar secret manager; rotacionar imediatamente as chaves.",
        "cwe": ["CWE-798"],
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "stride": ["Information Disclosure", "Elevation of Privilege"],
    },
    "SRV-002": {
        "vulnerability": "Chaves privadas/certificados versionados.",
        "risk": "Impersonation/MITM; decriptação indevida; comprometimento da infraestrutura.",
        "remediation": "Não versionar chaves; usar vault/KMS; revogar e rotacionar imediatamente.",
        "cwe": ["CWE-321"],
        "references": ["https://cwe.mitre.org/data/definitions/321.html"],
        "stride": ["Information Disclosure", "Spoofing", "Elevation of Privilege"],
    },
    "SRV-003": {
        "vulnerability": "Atribuição direta de valores sensíveis.",
        "risk": "Vazamento incidental via VCS/SDLC/observabilidade.",
        "remediation": "Externalizar segredos; secret manager; limpeza de histórico.",
        "cwe": ["CWE-312", "CWE-798"],
        "references": ["https://cwe.mitre.org/data/definitions/312.html"],
        "stride": ["Information Disclosure", "Elevation of Privilege"],
    },
    "SRV-004": {
        "vulnerability": "Variável sensível vazia/nula.",
        "risk": "Fallbacks inseguros e exposição de dados por configuração.",
        "remediation": "Validar obrigatoriedade e formato; falhar build/deploy se ausente.",
        "cwe": ["CWE-200"],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-010": {
        "vulnerability": "Redirect aberto com destino controlável.",
        "risk": "Phishing; roubo de sessão e credenciais.",
        "remediation": "Allowlist de destinos; normalizar e validar alvo.",
        "cwe": ["CWE-601"],
        "references": ["https://cwe.mitre.org/data/definitions/601.html"],
        "stride": ["Spoofing"],
    },
    "SRV-011": {
        "vulnerability": "Uso direto de parâmetros de entrada.",
        "risk": "Amplia superfície para injeções/manipulação.",
        "remediation": "Validação/normalização tipada; DTOs/binders seguros.",
        "cwe": ["CWE-20"],
        "references": ["https://cwe.mitre.org/data/definitions/20.html"],
        "stride": ["Tampering"],
    },
    "SRV-020": {
        "vulnerability": "Algoritmos fracos (MD5/SHA‑1/ROT13/CRC32).",
        "risk": "Quebra de integridade (colisões) e falsificação.",
        "remediation": "SHA‑256/512; para senhas, bcrypt/Argon2/PBKDF2 com sal/custo.",
        "cwe": ["CWE-327", "CWE-328"],
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
        "stride": ["Tampering"],
    },
    "SRV-021": {
        "vulnerability": "Base64 tratado como criptografia.",
        "risk": "Reversão trivial; exposição de dados.",
        "remediation": "Criptografia autenticada (AES‑GCM/ChaCha20‑Poly1305).",
        "cwe": ["CWE-327"],
        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-022": {
        "vulnerability": "Pseudocriptografia 'caseira' por operações.",
        "risk": "Proteção ilusória; engenharia reversa fácil.",
        "remediation": "Usar bibliotecas criptográficas reconhecidas.",
        "cwe": ["CWE-327", "CWE-330"],
        "references": ["https://cwe.mitre.org/data/definitions/330.html"],
        "stride": ["Tampering", "Information Disclosure"],
    },
    "SRV-030": {
        "vulnerability": "Construção insegura de SQL (concatenação).",
        "risk": "SQLi → exfiltração/alteração de dados; potencial RCE.",
        "remediation": "Queries parametrizadas/ORM; validação; least privilege no DB.",
        "cwe": ["CWE-89"],
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "stride": ["Tampering", "Information Disclosure", "Elevation of Privilege"],
    },
    "SRV-031": {
        "vulnerability": "Execução dinâmica de código (eval/exec/new Function).",
        "risk": "Code Injection e tomada de controle do processo.",
        "remediation": "Remover eval/exec; mapeamentos determinísticos; sanitização forte.",
        "cwe": ["CWE-94"],
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
        "stride": ["Elevation of Privilege", "Tampering"],
    },
    "SRV-032": {
        "vulnerability": "Execução de comandos do SO via shell.",
        "risk": "Command Injection; LPE/movimentação lateral/DoS.",
        "remediation": "Sem shell; lista de argumentos; validar/escapar entradas.",
        "cwe": ["CWE-78"],
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
        "stride": ["Elevation of Privilege", "Tampering", "Denial of Service"],
    },
    "SRV-033": {
        "vulnerability": "Concatenação em comandos do SO.",
        "risk": "Injeção de parâmetros controlados pelo usuário.",
        "remediation": "Construir por lista de args; whitelists.",
        "cwe": ["CWE-78"],
        "references": ["https://cwe.mitre.org/data/definitions/78.html"],
        "stride": ["Tampering", "Elevation of Privilege"],
    },
    "SRV-040": {
        "vulnerability": "Acesso a arquivos sem validação de caminho.",
        "risk": "Path Traversal → exposição ou alteração indevida.",
        "remediation": "Normalizar/restringir caminhos (allowlist).",
        "cwe": ["CWE-22"],
        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
        "stride": ["Information Disclosure", "Tampering"],
    },
    "SRV-041": {
        "vulnerability": "Upload sem validação/restrição.",
        "risk": "Web shells/RCE; sobreposição de arquivos; DoS.",
        "remediation": "Validar MIME/assinatura; AV; storage fora do webroot; renomear seguro.",
        "cwe": ["CWE-434"],
        "references": ["https://cwe.mitre.org/data/definitions/434.html"],
        "stride": ["Elevation of Privilege", "Tampering", "Denial of Service"],
    },
    "SRV-042": {
        "vulnerability": "Listagem de diretório habilitada.",
        "risk": "Exposição de estrutura/artefatos úteis a ataque.",
        "remediation": "Desabilitar autoindex; index seguro.",
        "cwe": ["CWE-548"],
        "references": ["https://cwe.mitre.org/data/definitions/548.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-050": {
        "vulnerability": "Cookie de sessão sem Secure.",
        "risk": "Roubo de sessão em conexões não criptografadas.",
        "remediation": "Secure/HttpOnly/SameSite + HTTPS estrito.",
        "cwe": ["CWE-614"],
        "references": ["https://cwe.mitre.org/data/definitions/614.html"],
        "stride": ["Information Disclosure", "Elevation of Privilege"],
    },
    "SRV-051": {
        "vulnerability": "Ausência/menção de headers de segurança.",
        "risk": "Aumenta risco de XSS/clickjacking/MIME sniffing.",
        "remediation": "Aplicar CSP, XFO, X-Content-Type-Options, HSTS.",
        "cwe": ["CWE-693"],
        "references": ["https://cwe.mitre.org/data/definitions/693.html"],
        "stride": ["Information Disclosure", "Elevation of Privilege"],
    },
    "SRV-052": {
        "vulnerability": "Desabilita verificação de certificado TLS.",
        "risk": "MITM; vazamento de dados; manipulação de tráfego.",
        "remediation": "Validar cadeia/hostname; não usar verify=False; pinning quando aplicável.",
        "cwe": ["CWE-295"],
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
        "stride": ["Spoofing", "Information Disclosure", "Tampering"],
    },
    "SRV-060": {
        "vulnerability": "Sinks de XSS (ex.: <script>, innerHTML, document.write).",
        "risk": "Roubo de sessão, defacement, pivô entre contas.",
        "remediation": "Escapar/encode por contexto; sanitização; CSP; templates seguros.",
        "cwe": ["CWE-79"],
        "references": ["https://cwe.mitre.org/data/definitions/79.html"],
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
    },
    "SRV-070": {
        "vulnerability": "Captura genérica de exceções.",
        "risk": "Oculta trilhas e evidencia; dificulta auditoria (repudiation).",
        "remediation": "Capturar tipos específicos; falhar de forma segura; logging adequado.",
        "cwe": ["CWE-703"],
        "references": ["https://cwe.mitre.org/data/definitions/703.html"],
        "stride": ["Repudiation"],
    },
    "SRV-071": {
        "vulnerability": "Debug/log verboso em produção.",
        "risk": "Exposição incidental de dados; rastro excessivo.",
        "remediation": "Desabilitar debug; mascarar/filtrar dados sensíveis.",
        "cwe": ["CWE-215"],
        "references": ["https://cwe.mitre.org/data/definitions/215.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-072": {
        "vulnerability": "Segredo/senha em comentários.",
        "risk": "Descoberta por varredura; vazamento acidental.",
        "remediation": "Remover; hooks pre-commit; varredura recorrente.",
        "cwe": ["CWE-200", "CWE-615"],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-080": {
        "vulnerability": "Menção de paths/endpoints sensíveis/administrativos.",
        "risk": "Apoia reconhecimento/enumeração na cadeia de ataque.",
        "remediation": "Proteger com auth/ACL; evitar log/telemetria de paths internos.",
        "cwe": ["CWE-200"],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "stride": ["Information Disclosure"],
    },
    "SRV-090": {
        "vulnerability": "Rota possivelmente sem autenticação (heurística).",
        "risk": "Acesso não autenticado a funções críticas.",
        "remediation": "Aplicar decorators/filtros de autenticação/autorização; testes de acesso.",
        "cwe": ["CWE-306"],
        "references": ["https://cwe.mitre.org/data/definitions/306.html"],
        "stride": ["Elevation of Privilege", "Information Disclosure"],
    },
}

# -----------------------
# Utilitários
# -----------------------
for r in RULES:
    r["rx"] = re.compile(r["re"], re.IGNORECASE)

def is_text_file(path: str, limit: int = 8192) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(limit)
        return b"\x00" not in chunk
    except Exception:
        return False

def should_skip(path: str) -> bool:
    parts = set(os.path.normpath(path).split(os.sep))
    return any(d in parts for d in SKIP_DIRS)

def scan_file(path: str) -> List[Dict]:
    findings: List[Dict] = []
    if not is_text_file(path):
        return findings
    try:
        if os.path.getsize(path) > MAX_BYTES:
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
            "stride": [],
        }]

    for idx, line in enumerate(lines, start=1):
        l = line.strip()
        for rule in RULES:
            if rule["rx"].search(line):
                meta = RULE_META.get(rule["id"], {})
                enriched_title = rule["name"]
                if meta.get("vulnerability"):
                    enriched_title += f" — {meta['vulnerability']}"
                findings.append({
                    "rule_id": rule["id"],
                    "title": enriched_title,
                    "severity": rule["sev"],
                    "file": path,
                    "line": idx,
                    "message": f"Possível ocorrência: {rule['name']}",
                    "snippet": l[:300],
                    "vulnerability": meta.get("vulnerability", rule["name"]),
                    "risk": meta.get("risk", ""),
                    "remediation": meta.get("remediation", ""),
                    "cwe": meta.get("cwe", []),
                    "references": meta.get("references", []),
                    "stride": meta.get("stride", []),
                })

    # Heurística: rotas sem autenticação (python)
    if path.endswith(".py"):
        findings.extend(detect_unauthenticated_routes(lines, path))
    return dedup(findings)

def dedup(findings: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f["file"], f["line"], f["rule_id"], f.get("snippet",""))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

def detect_unauthenticated_routes(lines: List[str], path: str) -> List[Dict]:
    out = []
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("def ") and "(" in s and s.endswith(":"):
            window = lines[max(0, i-3):i]
            decorators = [w.strip() for w in window if w.strip().startswith("@")]
            protected = any(re.search(r"@(login_required|jwt_required|auth(\.|_)required)", d) for d in decorators)
            if not protected:
                meta = RULE_META.get("SRV-090", {})
                enriched_title = "rota sem autenticação (heurístico)"
                if meta.get("vulnerability"):
                    enriched_title += f" — {meta['vulnerability']}"
                out.append({
                    "rule_id": "SRV-090",
                    "title": enriched_title,
                    "severity": "HIGH",
                    "file": path,
                    "line": i+1,
                    "message": "Função de rota possivelmente sem decorator de autenticação (@login_required/@jwt_required/@auth_required).",
                    "snippet": s[:300],
                    "vulnerability": meta.get("vulnerability",""),
                    "risk": meta.get("risk",""),
                    "remediation": meta.get("remediation",""),
                    "cwe": meta.get("cwe", []),
                    "references": meta.get("references", []),
                    "stride": meta.get("stride", []),
                })
    return out

def walk_files(root: str, exts: Iterable[str]) -> Iterable[str]:
    exts = tuple(exts)
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            full = os.path.join(r, f)
            if should_skip(full):
                continue
            if f.lower().endswith(exts):
                yield full

def summarize(findings: List[Dict]) -> Dict[str, int]:
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts

def to_json(findings: List[Dict]) -> Dict:
    return {"results": findings}

def _sarif_help_md(meta: Dict) -> str:
    vuln = meta.get("vulnerability","")
    risk = meta.get("risk","")
    fix  = meta.get("remediation","")
    refs = meta.get("references",[])
    stride = meta.get("stride",[])
    out = []
    if vuln: out.append(f"**Vulnerabilidade:** {vuln}")
    if risk: out.append(f"**Risco:** {risk}")
    if fix:  out.append(f"**Mitigação:** {fix}")
    if stride: out.append(f"**STRIDE:** {', '.join(stride)}")
    if refs:
        out.append("**Referências:**")
        out.extend([f"- {u}" for u in refs])
    return "\n".join(out) or "Consulte a documentação interna de segurança."

def to_sarif(findings: List[Dict]) -> Dict:
    # Regras únicas com help/descrição e STRIDE
    rules_map: Dict[str, Dict] = {}
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_map:
            # preferir metadados do RULE_META; fallback no próprio finding
            meta = RULE_META.get(rid, {})
            rules_map[rid] = {
                "id": rid,
                "name": f.get("title", rid),
                "shortDescription": {"text": f.get("title", rid)},
                "fullDescription": {"text": f.get("vulnerability", f.get("title", rid))},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f["severity"], "note")},
                "help": {"text": _sarif_help_md(meta), "markdown": _sarif_help_md(meta)},
                "properties": {
                    "problem.severity": f.get("severity", "INFO"),
                    "stride": meta.get("stride", f.get("stride", [])),
                    "tags": [*f.get("cwe", []), "security", "custom-review"],
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
                "snippet": f.get("snippet",""),
                "cwe": f.get("cwe", []),
                "vulnerability": f.get("vulnerability",""),
                "risk": f.get("risk",""),
                "remediation": f.get("remediation",""),
                "references": f.get("references", []),
                "stride": f.get("stride", []),
            }
        })

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Custom Security Review (STRIDE-enriched)",
                "informationUri": "https://example.local/custom-security-review",
                "rules": list(rules_map.values())
            }},
            "results": results
        }]
    }

def main():
    ap = argparse.ArgumentParser("custom_security_review")
    ap.add_argument("--root", default=".", help="Diretório raiz do projeto")
    ap.add_argument("--json-out", default="custom-review.json", help="Arquivo JSON de saída")
    ap.add_argument("--sarif-out", default="custom-review.sarif", help="Arquivo SARIF 2.1.0 de saída")
    ap.add_argument("--max-bytes", type=int, default=MAX_BYTES, help="Tamanho máximo por arquivo")
    ap.add_argument("--include-extensions", default=",".join(DEFAULT_EXTS), help="Extensões que serão analisadas (csv)")
    ap.add_argument("--exclude-dirs", default=",".join(sorted(SKIP_DIRS)), help="Pastas a ignorar (csv)")
    ap.add_argument("--fail-on", choices=SEV_ORDER, help="Falha (exit 1) se houver achados >= severidade informada")
    args = ap.parse_args()

    global SKIP_DIRS, MAX_BYTES
    MAX_BYTES = int(args.max_bytes)
    exts = [e.strip().lower() for e in args.include_extensions.split(",") if e.strip()]
    SKIP_DIRS = set([d.strip() for d in args.exclude_dirs.split(",") if d.strip()])

    all_findings: List[Dict] = []
    for p in walk_files(args.root, exts):
        all_findings.extend(scan_file(p))
    all_findings = dedup(all_findings)

    # Saídas
    with open(args.json_out, "w", encoding="utf-8") as fj:
        json.dump(to_json(all_findings), fj, ensure_ascii=False, indent=2)

    with open(args.sarif_out, "w", encoding="utf-8") as fsr:
        json.dump(to_sarif(all_findings), fsr, ensure_ascii=False, indent=2)

    counts = summarize(all_findings)
    total = sum(counts.values())
    print(f"[custom-review] encontrados {total} achados -> {counts}")

    if args.fail_on:
        if any(sev_gte(s, args.fail_on) and c > 0 for s, c in counts.items()):
            sys.exit(1)

if __name__ == "__main__":
    main()
