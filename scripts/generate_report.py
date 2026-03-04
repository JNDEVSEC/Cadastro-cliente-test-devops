#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Relatório de Segurança (Corporate) — ENHANCED
- Capa corporativa com logo, empresa, datas e metadados do pipeline.
- Sumário (TOC), Resumo executivo com gráficos, e seções por tipo: SCA, SAST, IaC, SECRETS.
- Integra: Semgrep (JSON), Custom Review (JSON enhanced), Trivy Image (SARIF),
  Trivy FS Vulnerabilities (SARIF), Trivy FS Secrets (SARIF), Trivy Config (SARIF),
  e opcionalmente Trivy Config (Dockerfile específico) se presente.
- Mostra por achado: severidade, localização, mensagem, vulnerabilidade explorável, risco e correção.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, PageBreak, ListFlowable, ListItem, Image, Flowable
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfbase.pdfmetrics import stringWidth

# Matplotlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# -------------------------------
# Config / Inputs
# -------------------------------
REPORT_PATH = "security-report.pdf"

SEM_GREP_JSON     = "semgrep.json"
CUSTOM_JSON       = "custom-review.json"
TRIVY_IMG_SARIF   = "trivy-image.sarif"
TRIVY_FS_VULN     = "trivy-fs-vuln.sarif"
TRIVY_FS_SECRETS  = "trivy-fs-secrets.sarif"
TRIVY_CFG_SARIF   = "trivy-config.sarif"  # IaC geral
TRIVY_CFG_DOCKER  = "trivy-config-dockerfile.sarif"  # IaC (Dockerfile específico, opcional)

CHART_DIR = "charts"
os.makedirs(CHART_DIR, exist_ok=True)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Brand via env
COMPANY_NAME = os.getenv("COMPANY_NAME", "ACME Corp.")
REPORT_TITLE = os.getenv("REPORT_TITLE", "Relatório de Segurança — Pipeline CI")
LOGO_PATH    = os.getenv("LOGO_PATH", "")  # optional

# GH metadata
REPO     = os.getenv("GITHUB_REPOSITORY", "")
BRANCH   = os.getenv("GITHUB_REF_NAME", os.getenv("GITHUB_REF", ""))
SHA      = os.getenv("GITHUB_SHA", "")[:8]
RUN_ID   = os.getenv("GITHUB_RUN_ID", "")
WORKFLOW = os.getenv("GITHUB_WORKFLOW", "")
RUN_URL  = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/") + f"/{REPO}/actions/runs/{RUN_ID}" if REPO and RUN_ID else ""

# -------------------------------
# Utils
# -------------------------------
def load_json(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def escape_xml(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def sev_color_hex(level: str) -> str:
    COLORS = {
        "CRITICAL": "990000",
        "HIGH":     "CC3333",
        "MEDIUM":   "E6A100",
        "LOW":      "1E90FF",
        "INFO":     "666666",
    }
    return COLORS.get((level or "").upper(), "000000")

def human_date_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# -------------------------------
# Normalization helpers
# -------------------------------

def summarize_by_sev(items: List[Dict[str,Any]]) -> Dict[str,int]:
    counts = {k:0 for k in SEVERITIES}
    for r in items:
        sev = (r.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

# --- Semgrep JSON ---

def summarize_semgrep(js: Dict) -> Dict[str, int]:
    return summarize_by_sev(normalize_semgrep(js))

def normalize_semgrep(js: Dict) -> List[Dict[str, Any]]:
    out = []
    if not js:
        return out
    for r in js.get("results", []):
        sev = (r.get("extra", {}).get("severity") or "").upper()
        out.append({
            "src": "Semgrep",
            "type": "SAST",
            "rule_id": r.get("check_id", ""),
            "severity": sev,
            "location": f"{r.get('path','')}:{(r.get('start') or {}).get('line','')}",
            "message": r.get("extra", {}).get("message", "") or "",
            "vulnerability": r.get("extra", {}).get("metadata", {}).get("vulnerability", ""),
            "risk": r.get("extra", {}).get("metadata", {}).get("impact", ""),
            "remediation": r.get("extra", {}).get("metadata", {}).get("fix", ""),
            "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", []),
            "references": r.get("extra", {}).get("metadata", {}).get("references", []),
            "raw": r
        })
    return out

# --- Custom JSON (enhanced) ---

def summarize_custom(js: Dict) -> Dict[str, int]:
    return summarize_by_sev(normalize_custom(js))

def normalize_custom(js: Dict) -> List[Dict[str, Any]]:
    out = []
    if not js:
        return out
    for r in js.get("results", []):
        out.append({
            "src": "Custom",
            "type": "SAST",
            "rule_id": r.get("rule_id", ""),
            "severity": (r.get("severity") or "").upper(),
            "location": f"{r.get('file','')}:{r.get('line','')}",
            "message": r.get("message", "") or "",
            "vulnerability": r.get("vulnerability", ""),
            "risk": r.get("risk", ""),
            "remediation": r.get("remediation", ""),
            "cwe": r.get("cwe", []),
            "references": r.get("references", []),
            "raw": r
        })
    return out

# --- SARIF (Trivy e outros) ---

def sarif_runs(path: str) -> List[Dict[str, Any]]:
    sarif = load_json(path)
    if not sarif:
        return []
    return sarif.get("runs", [])


def sarif_results_with_rules(path: str) -> List[Dict[str, Any]]:
    runs = sarif_runs(path)
    out: List[Dict[str,Any]] = []
    for run in runs:
        rules_index = {}
        driver = (run.get("tool", {}) or {}).get("driver", {})
        for rule in (driver.get("rules") or []):
            rid = rule.get("id")
            if rid:
                rules_index[rid] = rule
        for res in (run.get("results") or []):
            rid   = res.get("ruleId", "")
            msg   = (res.get("message", {}) or {}).get("text", "") or ""
            locs  = res.get("locations", []) or []
            uri   = ""
            if locs:
                uri = (locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") or "")
                start_line = (locs[0].get("physicalLocation", {}).get("region", {}) or {}).get("startLine", "")
                if start_line:
                    uri = f"{uri}:{start_line}"
            # Severity: preferir result.properties se existir
            sev = (res.get("properties", {}) or {}).get("problem.severity", "")
            if not sev:
                # fallback para rule.properties ou nível
                rule = rules_index.get(rid, {})
                props = rule.get("properties", {}) if isinstance(rule, dict) else {}
                sev   = (props.get("problem.severity") or props.get("security-severity") or props.get("severity") or "").upper()
            sev = (sev or "").upper() or {"ERROR":"HIGH","WARNING":"MEDIUM","NOTE":"LOW"}.get((res.get("level") or "").upper(), "LOW")

            # Extra: tentar capturar help e referências
            rule = rules_index.get(rid, {})
            help_text = ""
            if isinstance(rule, dict):
                help_obj = rule.get("help", {})
                help_text = help_obj.get("markdown") or help_obj.get("text") or ""
            # propriedades (CWE, etc.)
            props_res = res.get("properties", {}) or {}
            props_rule = rule.get("properties", {}) if isinstance(rule, dict) else {}

            out.append({
                "rule_id": rid,
                "severity": sev,
                "location": uri,
                "message": msg,
                "help": help_text,
                "cwe": props_res.get("cwe") or props_rule.get("cwe") or [],
                "vulnerability": props_res.get("vulnerability", ""),
                "risk": props_res.get("risk", ""),
                "remediation": props_res.get("remediation", ""),
                "references": props_res.get("references", []) or props_rule.get("tags", []),
                "raw": res,
            })
    return out


def normalize_trivy_image() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results_with_rules(TRIVY_IMG_SARIF)
    for r in res:
        r["src"] = "Trivy Image"
        r["type"] = "SCA"
    return res, summarize_by_sev(res)


def normalize_trivy_fs_vuln() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results_with_rules(TRIVY_FS_VULN)
    for r in res:
        r["src"] = "Trivy FS (Vulns)"
        r["type"] = "SCA"
    return res, summarize_by_sev(res)


def normalize_trivy_fs_secrets() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results_with_rules(TRIVY_FS_SECRETS)
    for r in res:
        r["src"] = "Trivy FS (Secrets)"
        r["type"] = "SECRETS"
        # Se não houver 'risk'/'remediation', preencher genéricos
        r.setdefault("risk", "Exposição de segredo pode permitir acesso não autorizado a serviços e dados.")
        r.setdefault("remediation", "Remover segredo do repositório; usar secret manager/variáveis de ambiente e rotacionar chaves.")
    return res, summarize_by_sev(res)


def normalize_trivy_cfg() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results_with_rules(TRIVY_CFG_SARIF)
    for r in res:
        r["src"] = "Trivy Config"
        r["type"] = "IaC"
    # Dockefile específico (opcional)
    if os.path.exists(TRIVY_CFG_DOCKER):
        extra = sarif_results_with_rules(TRIVY_CFG_DOCKER)
        for r in extra:
            r["src"] = "Trivy Config (Dockerfile)"
            r["type"] = "IaC"
        res.extend(extra)
    return res, summarize_by_sev(res)

# -------------------------------
# Type classification (SCA/SAST/IaC/SECRETS)
# -------------------------------

TYPES = ["SCA", "SAST", "IaC", "SECRETS"]

# -------------------------------
# Risk & Fix (fallbacks)
# -------------------------------

def risk_text(sev: str) -> str:
    m = {
        "CRITICAL": "Risco crítico: exploração pode causar comprometimento total, exfiltração de dados ou RCE sem interação.",
        "HIGH":     "Risco alto: exploração provável com impacto significativo em confidencialidade, integridade ou disponibilidade.",
        "MEDIUM":   "Risco médio: exploração depende de condições adicionais; impacto moderado.",
        "LOW":      "Risco baixo: difícil de explorar ou impacto limitado; ainda assim recomenda-se correção.",
        "INFO":     "Informativo: melhoria recomendada, sem evidência de risco imediato."
    }
    return m.get((sev or "").upper(), "Risco não classificado.")


def recommend_fix(tp: str, rule_id: str, message: str, location: str) -> str:
    txt = (message or "").lower()
    rid = (rule_id or "").upper()
    if tp == "SAST":
        if "verify=false" in txt or "ssl.verify=false" in txt:
            return "Habilite verificação de certificado TLS (verify=True) e valide CA/hostnames."
        if "md5" in txt or "sha1" in txt:
            return "Substitua MD5/SHA1 por SHA-256/512; para senhas use bcrypt/Argon2/PBKDF2 com sal/custo."
        if "eval(" in txt or "exec(" in txt or "function(" in txt:
            return "Remova eval/exec; use parsing seguro/dispatch controlado; sanitize entradas."
        if "os.system" in txt or "subprocess.popen" in txt or "runtime.getruntime().exec" in txt:
            return "Evite shell/concentração; use subprocess com lista de argumentos e sanitize."
        if "innerhtml" in txt or "document.write" in txt or "<script>" in txt or "dangerouslysetinnerhtml" in txt:
            return "Mitigue XSS: sanitize/escape por contexto, templates seguros e CSP."
        if "select * from" in txt or ("where" in txt and ("$" in txt or "+" in txt)):
            return "Use queries parametrizadas; não concatene entrada de usuário em SQL."
        if rid.startswith("SRV-050"):
            return "Defina session.cookie_secure=True e configure HttpOnly/SameSite."
        if rid.startswith("SRV-041"):
            return "Restringir uploads: tipo, tamanho, antivírus e armazenamento seguro fora do webroot."
        return "Aplique correção específica da regra; valide entrada e minimize privilégios."
    if tp == "SCA":
        if rid.startswith("CVE-"):
            return "Atualize o pacote afetado para versão corrigida; aplique patches da distribuição; fixe versões."
        return "Atualize dependências vulneráveis; gere SBOM e monitore CVEs continuamente."
    if tp == "IaC":
        if "root" in txt:
            return "Evite rodar como root: crie usuário dedicado (USER) e ajuste permissões."
        if "latest" in txt:
            return "Evite tag 'latest'; fixe versões/digests para builds reprodutíveis."
        if "add " in txt and "http" in txt:
            return "Evite ADD de URLs; prefira COPY e downloads verificados (HTTPS + checksum)."
        if "777" in txt or "world-writable" in txt:
            return "Evite permissões 777; use privilégios mínimos (ex.: 640/750)."
        if "healthcheck" in txt:
            return "Adicione HEALTHCHECK adequado (ex.: curl -f /health || exit 1)."
        return "Aplique hardening: least privilege, versões fixas, validação e segurança da cadeia de supply."
    if tp == "SECRETS":
        return "Remover segredo do repositório; migrar para secret manager/variáveis de ambiente e rotacionar chaves afetadas."
    return "Aplique correção específica conforme o contexto do achado."

# -------------------------------
# Charts
# -------------------------------

def chart_overall(counts_by_type: Dict[str, Dict[str,int]], out_path: str):
    totals = {s:0 for s in SEVERITIES}
    for tcounts in counts_by_type.values():
        for s in SEVERITIES:
            totals[s] += tcounts.get(s, 0)
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    bars = ax.bar(SEVERITIES, [totals[s] for s in SEVERITIES],
                  color=["#8B0000","#DC143C","#FFA500","#1E90FF","#808080"])
    ax.set_title("Achados por severidade (geral)", fontsize=11)
    ax.set_ylabel("Quantidade")
    for b in bars:
        h = b.get_height()
        ax.annotate(str(int(h)), xy=(b.get_x()+b.get_width()/2, h), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=160)
    plt.close(fig)


def chart_by_type(counts_by_type: Dict[str, Dict[str,int]], out_path: str):
    types = list(counts_by_type.keys())
    if not types:
        return
    x = range(len(types))
    width = 0.15
    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    colors_map = {"CRITICAL":"#8B0000","HIGH":"#DC143C","MEDIUM":"#FFA500","LOW":"#1E90FF","INFO":"#808080"}
    for i, sev in enumerate(SEVERITIES):
        vals = [counts_by_type[t].get(sev,0) for t in types]
        ax.bar([xi + i*width for xi in x], vals, width=width, label=sev, color=colors_map[sev])
    ax.set_title("Achados por tipo e severidade", fontsize=11)
    ax.set_xticks([xi + 2*width for xi in x])
    ax.set_xticklabels(types, rotation=0, ha="center")
    ax.legend(fontsize=8, ncol=3)
    ax.set_ylabel("Quantidade")
    fig.tight_layout()
    fig.savefig(out_path, dpi=160)
    plt.close(fig)

# -------------------------------
# Layout: capa + páginas internas
# -------------------------------

def draw_header_footer(canvas, doc):
    canvas.saveState()
    # Cabeçalho
    header_text = f"{COMPANY_NAME} — {REPORT_TITLE}"
    canvas.setFont("Helvetica", 9)
    canvas.drawString(doc.leftMargin, A4[1] - doc.topMargin + 10, header_text)
    # Logo (opcional)
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            canvas.drawImage(LOGO_PATH, A4[0] - doc.rightMargin - 2.2*cm, A4[1] - doc.topMargin + 2,
                             width=2*cm, height=2*cm, preserveAspectRatio=True, mask='auto')
        except Exception:
            pass
    # Rodapé: página
    page_text = f"Página {canvas.getPageNumber()}"
    w = stringWidth(page_text, "Helvetica", 9)
    canvas.drawString(A4[0] - doc.rightMargin - w, doc.bottomMargin - 14, page_text)
    canvas.restoreState()


def draw_cover(canvas, doc):
    # Capa sem header/footer
    pass


class CorporateDoc(BaseDocTemplate):
    def __init__(self, filename, **kw):
        super().__init__(filename, **kw)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id='frame')
        cover_tmpl = PageTemplate(id='cover', frames=[frame], onPage=draw_cover)
        page_tmpl  = PageTemplate(id='page',  frames=[frame], onPage=draw_header_footer)
        self.addPageTemplates([cover_tmpl, page_tmpl])
        self._toc = TableOfContents()
        self._toc.levelStyles = [
            ParagraphStyle(fontName='Helvetica-Bold', fontSize=12, name='TOCHeading1',
                           leftIndent=0, firstLineIndent=0, spaceBefore=4, leading=14),
            ParagraphStyle(fontName='Helvetica', fontSize=10, name='TOCHeading2',
                           leftIndent=12, firstLineIndent=-12, spaceBefore=2, leading=12),
        ]

    def afterFlowable(self, flowable: Flowable):
        if isinstance(flowable, Paragraph) and hasattr(flowable, "toc_level") and hasattr(flowable, "toc_text"):
            self.notify('TOCEntry', (flowable.toc_level, flowable.toc_text, self.page))


def make_heading(text: str, level: int, styles) -> Paragraph:
    style_name = "H1" if level == 1 else "H2"
    p = Paragraph(text, styles[style_name])
    p.toc_level = level
    p.toc_text  = text
    return p

# -------------------------------
# Findings rendering
# -------------------------------

def bullet_for_finding(styles, tp: str, it: Dict[str,Any]) -> ListItem:
    rule_id  = it.get("rule_id") or 'N/A'
    severity = it.get("severity") or 'INFO'
    location = it.get("location") or ''
    message  = it.get("message") or ''
    vuln     = it.get("vulnerability") or ''
    risk     = it.get("risk") or risk_text(severity)
    fix      = it.get("remediation") or recommend_fix(tp, rule_id, message + " " + vuln, location)
    cwe_list = it.get("cwe") or []
    refs     = it.get("references") or []
    help_md  = it.get("help") or ''

    head = f"[{severity}] <b>{escape_xml(rule_id)}</b> — <i>{escape_xml(tp)}</i>"
    lines = [
        f"<font color='#{sev_color_hex(severity)}'>{head}</font>",
        escape_xml(location),
    ]
    if message:
        lines.append(escape_xml(message))
    if vuln:
        lines.append(f"<b>Vulnerabilidade:</b> {escape_xml(vuln)}")
    lines.append(f"<b>Risco:</b> {escape_xml(risk)}")
    lines.append(f"<b>Correção recomendada:</b> {escape_xml(fix)}")
    if cwe_list:
        lines.append(f"<b>CWE:</b> {escape_xml(','.join(cwe_list))}")
    if refs:
        lines.append(f"<b>Referências:</b> {escape_xml(', '.join(map(str, refs)))}")
    elif help_md:
        # fallback: extrair 1a linha "help"
        lines.append(escape_xml(help_md.splitlines()[0][:300]))

    html = "<br/>".join(lines)
    return ListItem(Paragraph(html, styles["Body"]), leftIndent=12)


def dedup_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for it in items:
        key = (it.get("src",""), it.get("type",""), it.get("rule_id",""), it.get("location",""), it.get("message",""))
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out

# -------------------------------
# Build PDF
# -------------------------------

def build_pdf():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1", fontSize=18, leading=22, spaceAfter=12, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16, spaceAfter=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=13))

    doc = CorporateDoc(REPORT_PATH, pagesize=A4,
                       leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)

    flow: List[Any] = []

    # ------------- CAPA (usa template 'cover' na 1ª página) -------------
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        flow.append(Image(LOGO_PATH, width=5*cm, height=5*cm))
        flow.append(Spacer(1, 8))
    flow.append(Paragraph(REPORT_TITLE, styles["H1"]))
    flow.append(Paragraph(human_date_utc(), styles["Body"]))

    if REPO:
        meta = []
        meta.append(f"Repositório: {escape_xml(REPO)}")
        if BRANCH:   meta.append(f"Branch/Ref: {escape_xml(BRANCH)}")
        if SHA:      meta.append(f"Commit: {escape_xml(SHA)}")
        if WORKFLOW: meta.append(f"Workflow: {escape_xml(WORKFLOW)}")
        if RUN_URL:  meta.append(f"Execução: {escape_xml(RUN_URL)}")
        flow.append(Paragraph(" — ".join(meta), styles["Body"]))

    flow.append(Spacer(1, 20))
    flow.append(Paragraph(COMPANY_NAME, styles["H2"]))
    flow.append(PageBreak())  # fim da capa

    # ------------- Carrega fontes (resultados) -------------
    semgrep_js = load_json(SEM_GREP_JSON)
    custom_js  = load_json(CUSTOM_JSON)

    semgrep_items = normalize_semgrep(semgrep_js)
    custom_items  = normalize_custom(custom_js)

    tri_img_items, _    = ([], {s:0 for s in SEVERITIES})
    tri_fs_vuln_items, _   = ([], {s:0 for s in SEVERITIES})
    tri_fs_secret_items, _ = ([], {s:0 for s in SEVERITIES})
    tri_cfg_items, _    = ([], {s:0 for s in SEVERITIES})

    if os.path.exists(TRIVY_IMG_SARIF):
        tri_img_items, _ = normalize_trivy_image()
    if os.path.exists(TRIVY_FS_VULN):
        tri_fs_vuln_items, _ = normalize_trivy_fs_vuln()
    if os.path.exists(TRIVY_FS_SECRETS):
        tri_fs_secret_items, _ = normalize_trivy_fs_secrets()
    if os.path.exists(TRIVY_CFG_SARIF) or os.path.exists(TRIVY_CFG_DOCKER):
        tri_cfg_items, _ = normalize_trivy_cfg()

    # Agrupa por tipo
    all_items = []
    all_items.extend(semgrep_items)
    all_items.extend(custom_items)
    all_items.extend(tri_img_items)
    all_items.extend(tri_fs_vuln_items)
    all_items.extend(tri_fs_secret_items)
    all_items.extend(tri_cfg_items)
    all_items = dedup_findings(all_items)

    by_type: Dict[str, List[Dict[str,Any]]] = {t: [] for t in TYPES}
    for it in all_items:
        tp = it.get("type")
        if tp in by_type:
            by_type[tp].append(it)

    counts_by_type: Dict[str, Dict[str,int]] = {}
    for t, items in by_type.items():
        counts_by_type[t] = summarize_by_sev(items)

    # ------------- Resumo executivo + gráficos -------------
    total_all = sum(sum(v.values()) for v in counts_by_type.values())
    crit_high = sum(counts_by_type.get(t,{}).get("CRITICAL",0) + counts_by_type.get(t,{}).get("HIGH",0) for t in TYPES)

    flow.append(Paragraph("Resumo executivo", styles["H2"]))
    flow.append(Paragraph(
        f"Total de achados: <b>{total_all}</b>. "
        f"CRITICAL+HIGH: <b>{crit_high}</b> (indicadores prioritários de remediação).",
        styles["Body"]
    ))
    flow.append(Spacer(1, 10))

    overall_chart = os.path.join(CHART_DIR, "overall_by_severity.png")
    bytype_chart  = os.path.join(CHART_DIR, "by_type_severity.png")
    if any(sum(v.values()) for v in counts_by_type.values()):
        chart_overall(counts_by_type, overall_chart)
        chart_by_type(counts_by_type, bytype_chart)
        if os.path.exists(overall_chart):
            flow.append(Image(overall_chart, width=15*cm, height=7*cm))
            flow.append(Spacer(1, 6))
        if os.path.exists(bytype_chart):
            flow.append(Image(bytype_chart, width=15*cm, height=7*cm))
    else:
        flow.append(Paragraph("Nenhum achado encontrado nas fontes analisadas.", styles["Body"]))
    flow.append(PageBreak())

    # ---------- TOC ----------
    flow.append(make_heading("Sumário", 1, styles))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(fontName='Helvetica-Bold', fontSize=12, name='TOCHeading1', leftIndent=0, firstLineIndent=0, spaceBefore=4, leading=14),
        ParagraphStyle(fontName='Helvetica', fontSize=10, name='TOCHeading2', leftIndent=12, firstLineIndent=-12, spaceBefore=2, leading=12),
    ]
    flow.append(toc)
    flow.append(PageBreak())

    # ---------- Seções ----------
    def add_type_section(title_key: str, title_label: str):
        items = by_type.get(title_key, [])
        if not items:
            return
        total = sum(1 for _ in items)
        flow.append(make_heading(f"{title_label} — {total} achados", 1, styles))
        for sev in SEVERITIES:
            subset = [f for f in items if (f.get("severity") or "").upper() == sev]
            if not subset:
                continue
            flow.append(make_heading(f"{title_label} — {sev}", 2, styles))
            subset.sort(key=lambda x: (x.get("location",""), x.get("rule_id","")))
            bullets = [bullet_for_finding(styles, title_label.split(" — ")[0], it) for it in subset]
            flow.append(ListFlowable(bullets, bulletType="bullet"))
            flow.append(Spacer(1, 8))
        flow.append(PageBreak())

    add_type_section("SCA", "SCA")
    add_type_section("SAST", "SAST")
    add_type_section("IaC", "IaC")
    add_type_section("SECRETS", "SECRETS")

    # ---------- Anexos (opcional): metadados de execução ----------
    flow.append(make_heading("Anexos", 1, styles))
    meta_lines = [
        f"Empresa: {escape_xml(COMPANY_NAME)}",
        f"Relatório: {escape_xml(REPORT_TITLE)}",
        f"Gerado em: {escape_xml(human_date_utc())}",
    ]
    if REPO:
        meta_lines.extend([
            f"Repositório: {escape_xml(REPO)}",
            f"Branch/Ref: {escape_xml(BRANCH)}",
            f"Commit: {escape_xml(SHA)}",
            f"Workflow: {escape_xml(WORKFLOW)}",
            f"Execução: {escape_xml(RUN_URL)}",
        ])
    flow.append(Paragraph("<br/>".join(meta_lines), styles["Body"]))

    doc.build(flow)


def main():
    build_pdf()
    print(f"[report] PDF gerado: {REPORT_PATH}")


if __name__ == "__main__":
    main()
