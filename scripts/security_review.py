#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    ".next", ".nuxt", ".yarn", ".pnpm-store", "coverage"
}
DEFAULT_MAX_BYTES = 1_000_000  # 1 MB por arquivo (ajuste se necessário)

# Severidade -> nível SARIF
SEV_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# -----------------------
# Regras (ID, nome, regex, severidade)
# -----------------------
RULES = [
    # Exposição/segredos
    {"id": "SRV-001", "name": "hardcoded api key", "re": r"(api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "sev": "CRITICAL"},
    {"id": "SRV-002", "name": "hardcoded certificado", "re": r"(BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY)", "sev": "CRITICAL"},
    {"id": "SRV-003", "name": "atribuição de chave sensível", "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*['\"][^'\"]{4,}['\"]", "sev": "HIGH"},
    {"id": "SRV-004", "name": "variável sensível vazia", "re": r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASS|ACCESS_KEY)\b\s*=\s*([\"']{2}|null)", "sev": "MEDIUM"},

    # Autenticação/autorização
    {"id": "SRV-010", "name": "redirect aberto", "re": r"redirect\((request\.GET|url)\)", "sev": "HIGH"},
    {"id": "SRV-011", "name": "parâmetro direto", "re": r"(request\.GET|request\.POST|\$_GET|\$_POST)", "sev": "LOW"},

    # Criptografia/algoritmos
    {"id": "SRV-020", "name": "uso de algoritmo inseguro", "re": r"\b(md5|sha1|rot13|crc32)\b\s*\(", "sev": "HIGH"},
    {"id": "SRV-021", "name": "base64 usado como 'cripto'", "re": r"\bbase64\b\s*\(", "sev": "MEDIUM"},
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
]

# Compila regex uma vez
for r in RULES:
    r["rx"] = re.compile(r["re"], re.IGNORECASE)

# Severidades ordenadas para gate
SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def sev_gte(a: str, b: str) -> bool:
    return SEV_ORDER.index(a) >= SEV_ORDER.index(b)

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
            "snippet": ""
        }]

    for idx, line in enumerate(lines, start=1):
        l = line.strip()
        for rr in rules:
            if rr["rx"].search(line):
                findings.append({
                    "rule_id": rr["id"],
                    "title": rr["name"],
                    "severity": rr["sev"],
                    "file": path,
                    "line": idx,
                    "message": f"Possível ocorrência: {rr['name']}",
                    "snippet": l[:300],
                })
    # Heurística: rotas sem autenticação (python)
    if path.endswith(".py"):
        findings.extend(detect_unauthenticated_routes(lines, path))
    return dedup(findings)

def dedup(findings: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for f in findings:
        key = (f["file"], f["line"], f["rule_id"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

def detect_unauthenticated_routes(lines: List[str], path: str) -> List[Dict]:
    out = []
    # Procura 'def <nome>(' com até 3 decoradores acima
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("def ") and "(" in s and s.endswith(":"):
            window = lines[max(0, i-3):i]
            decorators = [w.strip() for w in window if w.strip().startswith("@")]
            protected = any(re.search(r"@(login_required|jwt_required|auth(\.|_)required)", d) for d in decorators)
            if not protected:
                out.append({
                    "rule_id": "SRV-090",
                    "title": "rota sem autenticação (heurístico)",
                    "severity": "HIGH",
                    "file": path,
                    "line": i+1,
                    "message": "Função de rota possivelmente sem decorator de autenticação (@login_required/@jwt_required/@auth_required).",
                    "snippet": s[:300],
                })
    return out

def walk_files(root: str, exts: Iterable[str], skip_dirs: Iterable[str]) -> Iterable[str]:
    exts = tuple(exts)
    skip_dirs = set(skip_dirs)
    for r, dirs, files in os.walk(root):
        # remove dirs ignorados in-place para evitar descer
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

def to_sarif(findings: List[Dict]) -> Dict:
    # Regras únicas
    rules_map = {}
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_map:
            rules_map[rid] = {
                "id": rid,
                "name": f.get("title", rid),
                "shortDescription": {"text": f.get("title", rid)},
                "fullDescription": {"text": f.get("message", f.get("title", rid))},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f["severity"], "note")},
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule_id"],
            "level": SEV_TO_SARIF.get(f["severity"], "note"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]}
                }
            }]
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Custom Security Review",
                    "informationUri": "https://example.local/custom-security-review",
                    "rules": list(rules_map.values())
                }
            },
            "results": results
        }]
    }
    return sarif

def write_csv(findings: List[Dict], csv_path: str) -> None:
    """Escreve CSV com colunas: Rule ID, Severity, File, Line, Message, Snippet"""
    fieldnames = ["Rule ID", "Severity", "File", "Line", "Message", "Snippet"]
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
            })

def main():
    ap = argparse.ArgumentParser("custom_security_review")
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
