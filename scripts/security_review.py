#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_review.py — Mini Pentest Estático
Saída compatível com a Plataforma de Vulnerabilidades (fonte: custom)

Uso:
  python security_review.py --root . --json-out custom-review.json --sarif-out custom-review.sarif
"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Iterable

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DEFAULT_EXTS = [".py", ".js", ".ts", ".jsx", ".tsx", ".php",
                ".java", ".go", ".rb", ".cs", ".env", ".yml", ".yaml",
                ".xml", ".tf", ".sh", ".bash"]
_SKIP_DIRS_DEFAULT = {
    ".git",".hg",".svn",".tox",".mypy_cache",".pytest_cache",
    "node_modules","dist","build","out",".venv","venv","__pycache__",
    ".next",".nuxt",".yarn",".pnpm-store","coverage","vendor",
    "migrations","staticfiles",".terraform",
    "scripts",".github"   # ← adicionar aqui
}
MAX_BYTES = 1_000_000
SEV_ORDER = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]

SEV_TO_SARIF = {
    "CRITICAL":"error","HIGH":"error","MEDIUM":"warning",
    "LOW":"note","INFO":"note",
}

_SKIP_DIRS = _SKIP_DIRS_DEFAULT.copy()

# ──────────────────────────────────────────────
# REGRAS
# Campos: id, name, re, sev, description, fix, cwe
# ──────────────────────────────────────────────
RULES = [

    # ── A01: Broken Access Control ──────────────────
    {
        "id":"AC-001","sev":"HIGH",
        "name":"Rota sem autenticação (heurístico)",
        "re": r"@(app|bp|router)\.(get|post|put|delete|patch)\s*\(",
        "description":"Endpoint HTTP definido sem decorator de autenticação visível nas 5 linhas anteriores.",
        "fix":"Adicione @login_required / @jwt_required / @auth.login_required antes da função.",
        "cwe":["CWE-306"],
    },
    {
        "id":"AC-002","sev":"HIGH",
        "name":"IDOR — acesso direto por ID do usuário",
        "re": r"(User\.get|get_object_or_404|Model\.find)\s*\(\s*(id|pk)\s*=\s*(request|req)\.",
        "description":"Objeto buscado diretamente por ID vindo da requisição sem verificação de ownership.",
        "fix":"Verifique se o objeto pertence ao usuário autenticado antes de retorná-lo.",
        "cwe":["CWE-639"],
    },
    {
        "id":"AC-003","sev":"MEDIUM",
        "name":"Bypass de is_admin/is_staff em query params",
        "re": r"(is_admin|is_staff|role|cargo)\s*=\s*(request\.(GET|POST|data|json|args|form))",
        "description":"Flag de privilégio controlada pelo cliente via parâmetros da requisição.",
        "fix":"Nunca aceite flags de privilégio do cliente; use a sessão/token do backend.",
        "cwe":["CWE-269"],
    },

    # ── A02: Cryptographic Failures ─────────────────
    {
        "id":"CR-001","sev":"CRITICAL",
        "name":"Chave/segredo hardcoded",
        "re": r"(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|pwd)\s*[:=]\s*['\"][A-Za-z0-9@#$%^&*_\-\.]{8,}['\"]",
        "description":"Credencial ou chave secreta embutida diretamente no código-fonte.",
        "fix":"Use variáveis de ambiente ou secret manager; rotacione a chave imediatamente.",
        "cwe":["CWE-798","CWE-259"],
    },
    {
        "id":"CR-002","sev":"CRITICAL",
        "name":"Chave privada/certificado no código",
        "re": r"(BEGIN (RSA |EC |DSA )?PRIVATE KEY|BEGIN CERTIFICATE|PRIVATE KEY-----)",
        "description":"Material criptográfico privado versionado no repositório.",
        "fix":"Revogar imediatamente; mover para vault/KMS; nunca versionar.",
        "cwe":["CWE-321"],
    },
    {
        "id":"CR-003","sev":"HIGH",
        "name":"Algoritmo hash inseguro (MD5/SHA1)",
        "re": r"\b(hashlib\.md5|hashlib\.sha1|md5\s*\(|sha1\s*\(|DigestUtils\.md5|MessageDigest\.getInstance\s*\(\s*[\"']MD5|[\"']SHA-1[\"'])\b",
        "description":"MD5 e SHA-1 são criptograficamente quebrados e vulneráveis a colisão.",
        "fix":"Use SHA-256/512 para integridade; bcrypt/Argon2/PBKDF2 para senhas.",
        "cwe":["CWE-327","CWE-328"],
    },
    {
        "id":"CR-004","sev":"HIGH",
        "name":"Verificação TLS desabilitada",
        "re": r"(verify\s*=\s*False|ssl\.CERT_NONE|checkCertificate\s*=\s*false|InsecureRequestWarning|urllib3\.disable_warnings)",
        "description":"Certificado TLS não é validado; vulnerável a MITM.",
        "fix":"Remova verify=False; use certificados válidos; implemente certificate pinning se necessário.",
        "cwe":["CWE-295"],
    },
    {
        "id":"CR-005","sev":"HIGH",
        "name":"Base64 usado como criptografia",
        "re": r"(base64\.(b64encode|b64decode|encodebytes))\s*\(",
        "description":"Base64 é codificação, não criptografia. Dados são trivialmente reversíveis.",
        "fix":"Use criptografia autenticada (AES-GCM, ChaCha20-Poly1305) para dados sensíveis.",
        "cwe":["CWE-327"],
    },
    {
        "id":"CR-006","sev":"MEDIUM",
        "name":"Gerador de número aleatório inseguro",
        "re": r"\b(random\.random|random\.randint|Math\.random|rand\(\)|srand\()\b",
        "description":"Geradores pseudo-aleatórios não criptográficos são previsíveis.",
        "fix":"Use secrets.token_bytes / secrets.token_hex (Python) ou crypto.getRandomValues() (JS).",
        "cwe":["CWE-338"],
    },

    # ── A03: Injection ───────────────────────────────
    {
        "id":"INJ-001","sev":"CRITICAL",
        "name":"SQL Injection por concatenação",
        "re": r"(execute|query|raw|cursor\.execute)\s*\(\s*[\"']?\s*SELECT|INSERT|UPDATE|DELETE.*[\"']?\s*\+|%\s*\w+|\.format\s*\(|f[\"'].*SELECT",
        "description":"Query SQL construída por concatenação ou f-string com dados do usuário.",
        "fix":"Use queries parametrizadas (?/%s) ou ORM com métodos seguros. Nunca concatene entrada do usuário.",
        "cwe":["CWE-89"],
    },
    {
        "id":"INJ-002","sev":"HIGH",
        "name":"Command Injection",
        "re": r"(os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec|exec\s*\(|popen\s*\()",
        "description":"Execução de comando de sistema com possível entrada do usuário.",
        "fix":"Nunca use shell=True; passe argumentos como lista; valide e sanitize entradas.",
        "cwe":["CWE-78"],
    },
    {
        "id":"INJ-003","sev":"HIGH",
        "name":"Code Injection (eval/exec)",
        "re": r"\b(eval|exec|compile)\s*\(\s*(request|req|user_input|\$_|input)",
        "description":"Execução dinâmica de código com entrada controlada pelo usuário.",
        "fix":"Elimine eval/exec; use mapeamentos de funções ou AST para parsing seguro.",
        "cwe":["CWE-94"],
    },
    {
        "id":"INJ-004","sev":"HIGH",
        "name":"SSTI — Server-Side Template Injection",
        "re": r"(render_template_string\s*\(|Template\s*\(\s*(request|user|f[\"'])|Jinja2\.from_string\s*\(.*\+)",
        "description":"Template renderizado com dados do usuário sem escape; pode levar a RCE.",
        "fix":"Nunca passe entrada do usuário em render_template_string; use templates estáticos.",
        "cwe":["CWE-94"],
    },
    {
        "id":"INJ-005","sev":"HIGH",
        "name":"SSRF — Server-Side Request Forgery",
        "re": r"(requests\.(get|post|put)\s*\(\s*(request\.|req\.|url\s*=\s*(request|req))|urllib\.request\.urlopen\s*\(\s*(request|req)|fetch\s*\(\s*req\.(body|query|params))",
        "description":"URL da requisição controlada pelo cliente; pode aceder serviços internos.",
        "fix":"Valide e allowlist URLs; bloqueie IPs privados (169.254.x, 10.x, 192.168.x); use proxy de egress.",
        "cwe":["CWE-918"],
    },
    {
        "id":"INJ-006","sev":"HIGH",
        "name":"NoSQL Injection (MongoDB/Mongoose)",
        "re": r"(find\s*\(\s*\{.*\$where|\$regex.*req\.|collection\.(find|findOne)\s*\(.*req\.(body|query|params))",
        "description":"Query NoSQL com operadores controlados pelo cliente.",
        "fix":"Valide e sanitize entradas; use esquemas estrito (Mongoose); bloqueie operadores $.",
        "cwe":["CWE-943"],
    },
    {
        "id":"INJ-007","sev":"HIGH",
        "name":"XSS — Sink perigoso",
        "re": r"(document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|dangerouslySetInnerHTML|\beval\s*\(\s*(location|document))",
        "description":"Dados inseridos diretamente no DOM sem sanitização; permite XSS.",
        "fix":"Use textContent em vez de innerHTML; sanitize com DOMPurify; implemente CSP.",
        "cwe":["CWE-79"],
    },
    {
        "id":"INJ-008","sev":"MEDIUM",
        "name":"Log Injection",
        "re": r"(logging\.(info|warning|error|debug|critical)|console\.(log|warn|error))\s*\(.*\+.*(request|req)\.",
        "description":"Dados do usuário inseridos em logs sem sanitização; pode forjar entradas de log.",
        "fix":"Sanitize dados antes de logar; use structured logging; escape newlines (\\n, \\r).",
        "cwe":["CWE-117"],
    },
    {
        "id":"INJ-009","sev":"HIGH",
        "name":"XXE — XML External Entity",
        "re": r"(etree\.(parse|fromstring)|XMLParser\s*\(|DocumentBuilder|SAXParser|lxml\.etree)(?!.*resolve_entities\s*=\s*False)",
        "description":"Parser XML pode processar entidades externas (XXE) se não configurado com segurança.",
        "fix":"Desabilite DTD/external entities: etree.XMLParser(resolve_entities=False, no_network=True).",
        "cwe":["CWE-611"],
    },
    {
        "id":"INJ-010","sev":"HIGH",
        "name":"Desserialização insegura",
        "re": r"\b(pickle\.(loads|load)|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)|marshal\.loads|jsonpickle\.decode|unserialize\s*\()",
        "description":"Desserialização de dados não confiáveis pode causar RCE.",
        "fix":"Use yaml.safe_load(); evite pickle com dados externos; use JSON com schema validation.",
        "cwe":["CWE-502"],
    },

    # ── A04: Insecure Design ─────────────────────────
    {
        "id":"DES-001","sev":"HIGH",
        "name":"Upload de arquivo sem restrição",
        "re": r"(move_uploaded_file|request\.files|multer\(\)|file\.upload|@RequestParam.*MultipartFile)",
        "description":"Upload de arquivo sem validação de tipo ou tamanho.",
        "fix":"Valide MIME/extensão; limite tamanho; armazene fora do webroot; renomeie aleatoriamente.",
        "cwe":["CWE-434"],
    },
    {
        "id":"DES-002","sev":"HIGH",
        "name":"Redirect aberto",
        "re": r"(redirect\s*\(\s*(request\.(GET|POST|args|query)|req\.(query|body))|HttpResponseRedirect\s*\(\s*request\.GET)",
        "description":"URL de redirecionamento controlada pelo usuário; facilita phishing.",
        "fix":"Use allowlist de domínios para redirect; não aceite URLs completas do usuário.",
        "cwe":["CWE-601"],
    },
    {
        "id":"DES-003","sev":"MEDIUM",
        "name":"Mass assignment / Over-posting",
        "re": r"(Model\(\*\*request\.(POST|data|json|form)|\.create\s*\(\s*\*\*request\.|update\s*\(\s*\*\*request\.)",
        "description":"Todos os campos do payload do cliente atribuídos diretamente ao modelo.",
        "fix":"Use serializers com campos explícitos (fields); nunca use **request.data direto.",
        "cwe":["CWE-915"],
    },

    # ── A05: Security Misconfiguration ──────────────
    {
        "id":"CFG-001","sev":"HIGH",
        "name":"DEBUG=True em produção",
        "re": r"\bDEBUG\s*=\s*True\b",
        "description":"Modo debug expõe stack traces, configurações e dados internos.",
        "fix":"Defina DEBUG=False em produção; use variável de ambiente.",
        "cwe":["CWE-215"],
    },
    {
        "id":"CFG-002","sev":"HIGH",
        "name":"CORS permissivo (wildcard)",
        "re": r"(CORS_ALLOW_ALL_ORIGINS\s*=\s*True|Access-Control-Allow-Origin.*\*|cors\(\{.*origin\s*:\s*['\*]|cors_allowed_origins\s*=\s*\[?\s*[\"']\*)",
        "description":"Qualquer origem pode fazer requisições cross-origin autenticadas.",
        "fix":"Liste origens explícitas; nunca use * com allow_credentials=True.",
        "cwe":["CWE-346"],
    },
    {
        "id":"CFG-003","sev":"HIGH",
        "name":"Cookie sem Secure/HttpOnly",
        "re": r"(SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|set_cookie\s*\((?!.*secure)|res\.cookie\s*\((?!.*httpOnly))",
        "description":"Cookie de sessão sem flags Secure/HttpOnly é vulnerável a roubo.",
        "fix":"Defina Secure=True, HttpOnly=True, SameSite=Strict/Lax.",
        "cwe":["CWE-614","CWE-1004"],
    },
    {
        "id":"CFG-004","sev":"MEDIUM",
        "name":"ALLOWED_HOSTS aberto (*)",
        "re": r"ALLOWED_HOSTS\s*=\s*\[?\s*['\"]?\*['\"]?\s*\]?",
        "description":"Qualquer host é aceito; facilita host header injection.",
        "fix":"Liste explicitamente os hosts permitidos.",
        "cwe":["CWE-183"],
    },
    {
        "id":"CFG-005","sev":"MEDIUM",
        "name":"CSRF desabilitado",
        "re": r"(csrf_exempt|@csrf_exempt|csrfmiddlewaretoken.*disabled|CSRF_COOKIE_SECURE\s*=\s*False|disableCSRF)",
        "description":"Proteção CSRF desabilitada; permite requisições forjadas de outros sites.",
        "fix":"Use @csrf_exempt apenas em endpoints de webhook com assinatura própria; documente a decisão.",
        "cwe":["CWE-352"],
    },
    {
        "id":"CFG-006","sev":"LOW",
        "name":"Porta de admin/debug exposta na configuração",
        "re": r"(0\.0\.0\.0:\d{4}|host\s*=\s*['\"]0\.0\.0\.0['\"]|BIND.*0\.0\.0\.0)",
        "description":"Serviço vinculado a todas as interfaces de rede.",
        "fix":"Vincule a 127.0.0.1 em desenvolvimento; use firewall/VPC em produção.",
        "cwe":["CWE-200"],
    },

    # ── A06: Vulnerable Components ───────────────────
    {
        "id":"DEP-001","sev":"MEDIUM",
        "name":"Versão de dependência sem pin (>=)",
        "re": r"^[a-zA-Z0-9_\-]+\s*>=\s*\d",
        "description":"Dependência com restrição aberta pode instalar versão vulnerável no futuro.",
        "fix":"Use versões pinadas (==x.y.z) ou faixas fechadas (>=x.y,<x+1).",
        "cwe":["CWE-1395"],
    },

    # ── A07: Auth Failures ───────────────────────────
    {
        "id":"AU-001","sev":"HIGH",
        "name":"JWT sem verificação de assinatura",
        "re": r"(jwt\.decode\s*\((?!.*algorithms|.*verify\s*=\s*True)|verify\s*=\s*False.*jwt|options\s*=\s*\{[\"']verify_signature[\"']\s*:\s*False)",
        "description":"Token JWT aceito sem verificar a assinatura; forjável por qualquer pessoa.",
        "fix":"Sempre passe algorithms=['HS256'] (ou RS256); nunca use verify=False.",
        "cwe":["CWE-347"],
    },
    {
        "id":"AU-002","sev":"HIGH",
        "name":"Senha armazenada em plaintext",
        "re": r"(password\s*=\s*['\"][^'\"]{4,}['\"]|SET password\s*=\s*['\"]|INSERT.*password.*VALUES\s*\(|db\.execute.*password.*[+%])",
        "description":"Senha armazenada ou transmitida sem hash.",
        "fix":"Use bcrypt/Argon2/PBKDF2; nunca armazene senha em plaintext ou MD5.",
        "cwe":["CWE-256","CWE-916"],
    },
    {
        "id":"AU-003","sev":"MEDIUM",
        "name":"Token/sessão em URL (query string)",
        "re": r"(token|session|access_token|api_key)\s*=\s*(request\.GET|req\.query|\$_GET)",
        "description":"Credencial transmitida na URL; aparece em logs, referrers e histórico.",
        "fix":"Use headers Authorization: Bearer <token>; nunca passe tokens em query string.",
        "cwe":["CWE-598"],
    },

    # ── A08: Software/Data Integrity ─────────────────
    {
        "id":"INT-001","sev":"HIGH",
        "name":"Desserialização YAML insegura",
        "re": r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.(SafeLoader|BaseLoader))",
        "description":"yaml.load() sem SafeLoader pode executar código arbitrário.",
        "fix":"Use yaml.safe_load() ou yaml.load(data, Loader=yaml.SafeLoader).",
        "cwe":["CWE-502"],
    },
    {
        "id":"INT-002","sev":"HIGH",
        "name":"Uso de pickle com dados externos",
        "re": r"pickle\.(loads|load)\s*\(",
        "description":"pickle pode executar código arbitrário ao desserializar dados não confiáveis.",
        "fix":"Nunca desserialize pickle de dados externos; use JSON com schema validation.",
        "cwe":["CWE-502"],
    },

    # ── A09: Logging ─────────────────────────────────
    {
        "id":"LOG-001","sev":"LOW",
        "name":"Dado sensível em log",
        "re": r"(log\.(info|debug|warning|error)|print\s*\(|console\.log)\s*\(.*\b(password|token|secret|credit_card|ssn|cpf|api_key)\b",
        "description":"Possível dado sensível sendo gravado em log.",
        "fix":"Mascare campos sensíveis; use logger estruturado com filtros de PII.",
        "cwe":["CWE-532"],
    },
    {
        "id":"LOG-002","sev":"LOW",
        "name":"Stack trace exposto ao usuário",
        "re": r"(traceback\.print_exc|e\.printStackTrace\(\)|res\.(send|json)\s*\(\s*err\b|res\.send\s*\(\s*error\b)",
        "description":"Stack trace da exceção enviado diretamente ao cliente.",
        "fix":"Log interno do erro; retorne mensagem genérica ao cliente.",
        "cwe":["CWE-209"],
    },

    # ── A10: SSRF / Path Traversal ───────────────────
    {
        "id":"PT-001","sev":"HIGH",
        "name":"Path Traversal — caminho do usuário sem validação",
        "re": r"(open\s*\(\s*(request|req|user|os\.path\.join\s*\(.*request)|send_file\s*\(\s*(request|req)|readFile\s*\(\s*(req|request))",
        "description":"Caminho de arquivo montado com input do usuário; permite ../../../etc/passwd.",
        "fix":"Use os.path.realpath() + verifique prefixo; use allowlist de caminhos permitidos.",
        "cwe":["CWE-22"],
    },

    # ── Infrastructure as Code ───────────────────────
    {
        "id":"IAC-001","sev":"HIGH",
        "name":"Bucket S3/storage público",
        "re": r"(acl\s*=\s*[\"']public-read|PublicAccessBlockConfiguration.*false|\"public-read-write\")",
        "description":"Bucket de armazenamento configurado como público.",
        "fix":"Defina ACL private; habilite Block Public Access; use presigned URLs.",
        "cwe":["CWE-732"],
    },
    {
        "id":"IAC-002","sev":"HIGH",
        "name":"Security group aberto (0.0.0.0/0)",
        "re": r"(cidr_blocks\s*=\s*\[?\s*[\"']0\.0\.0\.0/0[\"']|from_port\s*=\s*0.*to_port\s*=\s*0|ingress.*0\.0\.0\.0/0)",
        "description":"Regra de firewall abre todas as portas para qualquer IP.",
        "fix":"Restrinja CIDRs ao mínimo necessário; use security groups específicos por serviço.",
        "cwe":["CWE-732"],
    },

    # ── Qualidade/Práticas ────────────────────────────
    {
        "id":"QA-001","sev":"LOW",
        "name":"Tratamento genérico de exceção",
        "re": r"(except\s+Exception\b|except\s*:\s*$|catch\s*\(\s*Exception\s+[a-z]|catch\s*\(e\)\s*\{\s*\})",
        "description":"Exceção capturada genericamente; oculta erros e dificulta depuração.",
        "fix":"Capture tipos específicos; logue adequadamente; falhe de forma segura.",
        "cwe":["CWE-703"],
    },
    {
        "id":"QA-002","sev":"LOW",
        "name":"Console.log / print em produção",
        "re": r"(console\.(log|warn|error)|print\s*\()\s*\(",
        "description":"Saída de debug pode expor dados sensíveis em produção.",
        "fix":"Remova logs de debug; use sistema de logging configurável por nível.",
        "cwe":["CWE-215"],
    },
    {
        "id":"QA-003","sev":"LOW",
        "name":"TODO/FIXME de segurança",
        "re": r"#\s*(TODO|FIXME|HACK|XXX|SECURITY|VULN|BUG).*",
        "description":"Marcação de problema pendente no código.",
        "fix":"Revise e resolva o item; registre no backlog de segurança.",
        "cwe":["CWE-1164"],
    },
    {
        "id":"QA-004","sev":"HIGH",
        "name":"Segredo/credencial em comentário",
        "re": r"(#|//|/\*)\s*.*(password|senha|secret|api.?key|token|credential)\s*[:=]\s*\S+",
        "description":"Credencial em comentário é versionada e visível em histórico do git.",
        "fix":"Remova; use git filter-branch ou BFG Repo-Cleaner para limpar histórico.",
        "cwe":["CWE-615"],
    },
]

# Pré-compila regex
for r in RULES:
    r["rx"] = re.compile(r["re"], re.IGNORECASE | re.MULTILINE)

# ──────────────────────────────────────────────
# SCAN
# ──────────────────────────────────────────────

def is_text(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" not in f.read(8192)
    except Exception:
        return False

def should_skip(path: str) -> bool:
    parts = set(os.path.normpath(path).split(os.sep))
    return bool(parts & _SKIP_DIRS)

def get_evidence(lines: List[str], line_no: int, ctx: int = 2) -> str:
    """Retorna o snippet com N linhas de contexto ao redor."""
    start = max(0, line_no - 1 - ctx)
    end   = min(len(lines), line_no + ctx)
    snip  = []
    for i, ln in enumerate(lines[start:end], start=start+1):
        marker = ">>> " if i == line_no else "    "
        snip.append(f"{marker}{i}: {ln.rstrip()}")
    return "\n".join(snip)

def scan_file(path: str, root: str) -> List[Dict]:
    if not is_text(path):
        return []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
    except OSError:
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
            content = "".join(lines)
    except Exception:
        return []

    rel_path = os.path.relpath(path, root).replace("\\", "/")
    findings = []
    seen = set()

    for rule in RULES:
        for m in rule["rx"].finditer(content):
            line_no = content[:m.start()].count("\n") + 1
            key = (rel_path, line_no, rule["id"])
            if key in seen:
                continue
            seen.add(key)

            evidence = get_evidence(lines, line_no, ctx=2)
            findings.append({
                "rule_id":     rule["id"],
                "title":       rule["name"],
                "description": rule["description"],
                "severity":    rule["sev"],
                "path":        rel_path,
                "line":        line_no,
                "evidence":    evidence,
                "fix":         rule["fix"],
                "cwe":         rule.get("cwe", []),
            })

    # Heurística extra: rotas sem auth em Python
    if path.endswith(".py"):
        for i, raw in enumerate(lines):
            s = raw.strip()
            if re.match(r"def\s+\w+\s*\(", s) and s.endswith(":"):
                window = "".join(lines[max(0, i-5):i])
                if re.search(r"@(app|router|bp)\.(get|post|put|delete|patch)", window):
                    if not re.search(r"@(login_required|jwt_required|require_http_methods|permission_required|auth\.)", window):
                        key = (rel_path, i+1, "AC-001")
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "rule_id":     "AC-001",
                                "title":       "Rota sem autenticação (heurístico)",
                                "description": "Função de rota HTTP sem decorator de autenticação detectado nas 5 linhas anteriores.",
                                "severity":    "HIGH",
                                "path":        rel_path,
                                "line":        i+1,
                                "evidence":    get_evidence(lines, i+1, ctx=3),
                                "fix":         "Adicione @login_required / @jwt_required antes da função.",
                                "cwe":         ["CWE-306"],
                            })

    return findings

def walk_files(root: str, exts: tuple) -> Iterable[str]:
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            full = os.path.join(r, f)
            if not should_skip(full) and f.lower().endswith(exts):
                yield full

# ──────────────────────────────────────────────
# SAÍDA JSON (formato plataforma)
# ──────────────────────────────────────────────

def to_platform_json(findings: List[Dict]) -> Dict:
    """
    Formato compatível com parse_custom() da plataforma.
    Campos: rule_id, title, description, severity, path, line, evidence, fix
    """
    results = []
    for f in findings:
        results.append({
            "rule_id":     f["rule_id"],
            "title":       f["title"],
            "description": f"{f['description']}\n\nEvidência:\n{f['evidence']}\n\nCorreção: {f['fix']}",
            "severity":    f["severity"],
            "path":        f["path"],
            "line":        f["line"],
            "evidence":    f["evidence"],
            "fix":         f["fix"],
            "cwe":         f.get("cwe", []),
        })
    return {"results": results}

# ──────────────────────────────────────────────
# SAÍDA SARIF
# ──────────────────────────────────────────────

def to_sarif(findings: List[Dict]) -> Dict:
    rules_map: Dict[str, Dict] = {}
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules_map:
            rules_map[rid] = {
                "id": rid,
                "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "fullDescription":  {"text": f["description"]},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f["severity"], "note")},
                "help": {
                    "text": f"{f['description']}\n\nCorreção: {f['fix']}",
                    "markdown": f"**Problema:** {f['description']}\n\n**Correção:** {f['fix']}\n\n**CWE:** {', '.join(f.get('cwe',[]))}",
                },
                "properties": {
                    "problem.severity": f["severity"],
                    "tags": [*f.get("cwe", []), "security"],
                },
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule_id"],
            "level":  SEV_TO_SARIF.get(f["severity"], "note"),
            "message": {"text": f"{f['description']} | Fix: {f['fix']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["path"]},
                    "region": {
                        "startLine": f["line"],
                        "snippet":   {"text": f.get("evidence","")},
                    },
                }
            }],
            "properties": {
                "evidence":    f.get("evidence",""),
                "fix":         f.get("fix",""),
                "cwe":         f.get("cwe",[]),
                "severity":    f["severity"],
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{"tool": {"driver": {
            "name": "Custom Security Review",
            "informationUri": "https://github.com/JNDEVSEC",
            "rules": list(rules_map.values()),
        }}, "results": results}],
    }

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser("security_review")
    ap.add_argument("--root",      default=".", help="Diretório raiz")
    ap.add_argument("--json-out",  default="custom-review.json")
    ap.add_argument("--sarif-out", default="custom-review.sarif")
    ap.add_argument("--csv-out",   help="CSV opcional")
    ap.add_argument("--fail-on",   choices=SEV_ORDER, help="Falha se houver achados >= severidade")
    ap.add_argument("--include-extensions", default=",".join(DEFAULT_EXTS))
    ap.add_argument("--exclude-dirs",       default=",".join(sorted(_SKIP_DIRS_DEFAULT)))
    args = ap.parse_args()

    exts   = tuple(e.strip().lower() for e in args.include_extensions.split(",") if e.strip())
    global _SKIP_DIRS
    _SKIP_DIRS = set(d.strip() for d in args.exclude_dirs.split(",") if d.strip())

    all_findings: List[Dict] = []
    for p in walk_files(args.root, exts):
        all_findings.extend(scan_file(p, args.root))

    # Deduplica
    seen = set()
    deduped = []
    for f in all_findings:
        k = (f["path"], f["line"], f["rule_id"])
        if k not in seen:
            seen.add(k)
            deduped.append(f)

    # Ordena por severidade desc, depois por arquivo e linha
    sev_idx = {s: i for i, s in enumerate(reversed(SEV_ORDER))}
    deduped.sort(key=lambda f: (sev_idx.get(f["severity"], 99), f["path"], f["line"]))

    # Saídas
    with open(args.json_out, "w", encoding="utf-8") as fj:
        json.dump(to_platform_json(deduped), fj, ensure_ascii=False, indent=2)

    with open(args.sarif_out, "w", encoding="utf-8") as fs:
        json.dump(to_sarif(deduped), fs, ensure_ascii=False, indent=2)

    if args.csv_out:
        import csv
        with open(args.csv_out, "w", encoding="utf-8", newline="") as fc:
            w = csv.writer(fc)
            w.writerow(["rule_id","severity","title","path","line","description","evidence","fix","cwe"])
            for f in deduped:
                w.writerow([
                    f["rule_id"], f["severity"], f["title"],
                    f["path"], f["line"], f["description"],
                    f.get("evidence","").replace("\n","\\n"),
                    f["fix"], ",".join(f.get("cwe",[])),
                ])

    # Resumo
    counts = {s: 0 for s in SEV_ORDER}
    for f in deduped:
        counts[f["severity"]] += 1
    total = sum(counts.values())

    print(f"[security_review] {total} achados: "
          + " | ".join(f"{s}:{counts[s]}" for s in reversed(SEV_ORDER) if counts[s] > 0))
    print(f"  JSON  → {args.json_out}")
    print(f"  SARIF → {args.sarif_out}")

    if args.fail_on:
        idx = SEV_ORDER.index(args.fail_on)
        if any(counts[s] > 0 for s in SEV_ORDER[idx:]):
            sys.exit(1)

if __name__ == "__main__":
    main()
