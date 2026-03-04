#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

SEM_GREP_JSON   = "semgrep.json"
CUSTOM_JSON     = "custom-review.json"
TRIVY_IMG_SARIF = "trivy-image.sarif"
TRIVY_FS_SARIF  = "trivy-fs.sarif"
TRIVY_CFG_SARIF = "trivy-config.sarif"  # IaC

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
    # Escape ONLY content — do not escape tags we use in Paragraph
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def sev_color_hex(level: str) -> str:
    COLORS = {
        "CRITICAL": "990000",
        "HIGH":     "CC3333",
        "MEDIUM":   "E6A100",
        "LOW":      "1E90FF",
        "INFO":     "666666",
    }
    return COLORS.get(level.upper(), "000000")

def human_date_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# -------------------------------
# Normalization
# -------------------------------
def summarize_semgrep(js: Dict) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITIES}
    if not js:
        return counts
    for r in js.get("results", []):
        sev = (r.get("extra", {}).get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

def normalize_semgrep(js: Dict) -> List[Dict[str, Any]]:
    out = []
    if not js:
        return out
    for r in js.get("results", []):
        out.append({
            "src": "Semgrep",
            "rule_id": r.get("check_id", ""),
            "severity": (r.get("extra", {}).get("severity") or "").upper(),
            "location": f"{r.get('path','')}:{(r.get('start') or {}).get('line','')}",
            "message": r.get("extra", {}).get("message", "") or "",
            "raw": r
        })
    return out

def summarize_custom(js: Dict) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITIES}
    if not js:
        return counts
    for r in js.get("results", []):
        sev = (r.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

def normalize_custom(js: Dict) -> List[Dict[str, Any]]:
    out = []
    if not js:
        return out
    for r in js.get("results", []):
        out.append({
            "src": "Custom",
            "rule_id": r.get("rule_id", ""),
            "severity": (r.get("severity") or "").upper(),
            "location": f"{r.get('file','')}:{r.get('line','')}",
            "message": r.get("message", "") or "",
            "raw": r
        })
    return out

def sarif_results(path: str) -> List[Dict[str, Any]]:
    sarif = load_json(path)
    if not sarif:
        return []
    out = []
    for run in sarif.get("runs", []):
        rules_index = {}
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in rules:
            rid = rule.get("id")
            if rid:
                rules_index[rid] = rule
        for res in run.get("results", []):
            rid   = res.get("ruleId", "")
            level = res.get("level", "note")
            msg   = (res.get("message", {}) or {}).get("text", "") or ""
            locs  = res.get("locations", []) or []
            uri   = ""
            if locs:
                uri = (locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") or "")
            rule  = rules_index.get(rid, {})
            props = rule.get("properties", {}) if isinstance(rule, dict) else {}
            sev   = (props.get("security-severity") or props.get("problem.severity") or props.get("severity") or "").upper()
            if not sev:
                sev = {"ERROR":"HIGH","WARNING":"MEDIUM","NOTE":"LOW"}.get(level.upper(), "LOW")
            out.append({
                "rule_id": rid,
                "severity": sev,
                "location": uri,
                "message": msg,
                "raw": res
            })
    return out

def normalize_trivy_image() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results(TRIVY_IMG_SARIF)
    counts = {k:0 for k in SEVERITIES}
    for r in res:
        if r["severity"] in counts: counts[r["severity"]] += 1
    for r in res: r["src"] = "Trivy Image"
    return res, counts

def normalize_trivy_fs() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results(TRIVY_FS_SARIF)
    counts = {k:0 for k in SEVERITIES}
    for r in res:
        if r["severity"] in counts: counts[r["severity"]] += 1
    for r in res: r["src"] = "Trivy FS"
    return res, counts

def normalize_trivy_cfg() -> Tuple[List[Dict], Dict[str,int]]:
    res = sarif_results(TRIVY_CFG_SARIF)
    counts = {k:0 for k in SEVERITIES}
    for r in res:
        if r["severity"] in counts: counts[r["severity"]] += 1
    for r in res: r["src"] = "Trivy Config"
    return res, counts

# -------------------------------
# Type classification (SCA/SAST/IaC)
# -------------------------------
def classify_type(src: str, rule_id: str, message: str) -> str:
    rid = (rule_id or "").upper()
    s = (src or "").lower()

    if "trivy config" in s:
        return "IaC"

    if rid.startswith("CVE-"):
        return "SCA"

    if s in ("semgrep", "custom"):
        return "SAST"

    if "trivy image" in s or "trivy fs" in s:
        return "SCA"

    return "SAST"

# -------------------------------
# Risk & Fix
# -------------------------------
def risk_text(sev: str) -> str:
    m = {
        "CRITICAL": "Risco crítico: exploração pode causar comprometimento total, exfiltração de dados ou RCE sem interação.",
        "HIGH":     "Risco alto: exploração provável com impacto significativo em confidencialidade, integridade ou disponibilidade.",
        "MEDIUM":   "Risco médio: exploração depende de condições adicionais; impacto moderado.",
        "LOW":      "Risco baixo: difícil de explorar ou impacto limitado; ainda assim recomenda-se correção.",
        "INFO":     "Informativo: melhoria recomendada, sem evidência de risco imediato."
    }
    return m.get(sev.upper(), "Risco não classificado.")

def recommend_fix(tp: str, rule_id: str, message: str, location: str) -> str:
    txt = (message or "").lower()
    rid = (rule_id or "").upper()
    if tp == "SAST":
        if "verify=false" in txt or "ssl.verify=false" in txt:
            return "Habilite verificação de certificado TLS (verify=True) e valide CA/hostnames."
        if "md5" in txt or "sha1" in txt:
            return "Substitua MD5/SHA1 por SHA-256/512 com sal; use libs modernas (bcrypt/Argon2/PBKDF2 para senhas)."
        if "eval(" in txt or "exec(" in txt or "function(" in txt:
            return "Remova eval/exec; use parsing seguro/dispatch controlado; sanitize entradas."
        if "os.system" in txt or "subprocess.popen" in txt or "runtime.getruntime().exec" in txt:
            return "Evite shell + concatenação; use listas (subprocess.run([...], check=True)) e sanitize argumentos."
        if "innerhtml" in txt or "document.write" in txt or "script" in txt or "dangerouslysetinnerhtml" in txt:
            return "Mitigue XSS: sanitize/escape, templates seguros, CSP adequada; evitar HTML bruto."
        if "select * from" in txt or ("where" in txt and ("$" in txt or "+" in txt)):
            return "Use queries parametrizadas; não concatene entrada de usuário em SQL."
        if rid.startswith("SRV-050"):
            return "Defina session.cookie_secure=True e configure HttpOnly/SameSite."
        if rid.startswith("SRV-041"):
            return "Restrinja uploads: tipo, tamanho, varredura de malware, armazenamento e validação de conteúdo."
        return "Aplique correção específica da regra; valide entrada e minimize privilégios."
    if tp == "SCA":
        if rid.startswith("CVE-"):
            return "Atualize o pacote afetado para versão corrigida; aplique patches da distribuição; use pinning de versões."
        return "Atualize dependências vulneráveis; gere SBOM e monitore CVEs continuamente."
    if tp == "IaC":
        if "root" in txt:
            return "Evite rodar como root: crie usuário dedicado e defina USER não-root; ajuste permissões."
        if "latest" in txt:
            return "Evite a tag 'latest'; pinne versões de base/pacotes para builds reprodutíveis."
        if "add " in txt and "http" in txt:
            return "Evite ADD de URLs/HTTP; prefira COPY e downloads verificados (HTTPS + checksum/assinatura)."
        if "777" in txt or "world-writable" in txt:
            return "Evite permissões 777; use privilégios mínimos (ex.: 640/750)."
        if "healthcheck" in txt:
            return "Adicione HEALTHCHECK para liveness/readiness (ex.: curl -f /health || exit 1)."
        return "Aplique hardening: least privilege, versões fixas, validação e segurança de cadeia de supply."
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
        # Frame padrão
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id='frame')
        # Templates: capa (sem header) e páginas (com header/footer)
        cover_tmpl = PageTemplate(id='cover', frames=[frame], onPage=draw_cover)
        page_tmpl  = PageTemplate(id='page',  frames=[frame], onPage=draw_header_footer)
        self.addPageTemplates([cover_tmpl, page_tmpl])
        # TOC
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
def bullet_for_finding(styles, tp: str, rule_id: str, severity: str, location: str, message: str) -> ListItem:
    head = f"[{severity}] <b>{escape_xml(rule_id or 'N/A')}</b> — <i>{escape_xml(tp)}</i>"
    loc  = f"{escape_xml(location or '')}"
    msg  = escape_xml(message or "")
    risk = risk_text(severity)
    fix  = recommend_fix(tp, rule_id, message, location)
    html = (
        f"<font color='#{sev_color_hex(severity)}'>{head}</font><br/>"
        f"{loc}<br/>"
        f"{msg}<br/>"
        f"<b>Risco:</b> {escape_xml(risk)}<br/>"
        f"<b>Correção recomendada:</b> {escape_xml(fix)}"
    )
    return ListItem(Paragraph(html, styles["Body"]), leftIndent=12)

def dedup_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for it in items:
        key = (it.get("rule_id",""), it.get("location",""), it.get("message",""))
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

    # ------------- CAPA (vai usar o template 'cover' na 1ª página) -------------
    # A primeira página usa 'cover', as próximas usarão 'page'
    # Conteúdo da capa:
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

    # ------------- Resumo executivo + gráficos (template 'page') -------------
    # Carrega fontes (resultados)
    semgrep_js = load_json(SEM_GREP_JSON)
    custom_js  = load_json(CUSTOM_JSON)
    semgrep_counts = summarize_semgrep(semgrep_js)
    custom_counts  = summarize_custom(custom_js)
    semgrep_findings = normalize_semgrep(semgrep_js)
    custom_findings  = normalize_custom(custom_js)

    tri_img_res, tri_img_counts = ([], {s:0 for s in SEVERITIES})
    tri_fs_res,  tri_fs_counts  = ([], {s:0 for s in SEVERITIES})
    tri_cfg_res, tri_cfg_counts = ([], {s:0 for s in SEVERITIES})

    if os.path.exists(TRIVY_IMG_SARIF):
        tri_img_res, tri_img_counts = normalize_trivy_image()
    if os.path.exists(TRIVY_FS_SARIF):
        tri_fs_res, tri_fs_counts = normalize_trivy_fs()
    if os.path.exists(TRIVY_CFG_SARIF):
        tri_cfg_res, tri_cfg_counts = normalize_trivy_cfg()

    # Classifica por tipo
    sast: List[Dict[str,Any]] = []
    for f in semgrep_findings + custom_findings:
        if classify_type(f.get("src"), f.get("rule_id"), f.get("message")) == "SAST":
            f["type"] = "SAST"; sast.append(f)

    sca: List[Dict[str,Any]] = []
    for f in tri_img_res + tri_fs_res:
        if classify_type(f.get("src"), f.get("rule_id"), f.get("message")) == "SCA":
            f["type"] = "SCA"; sca.append(f)

    iac: List[Dict[str,Any]] = []
    for f in tri_cfg_res:
        if classify_type(f.get("src"), f.get("rule_id"), f.get("message")) == "IaC":
            f["type"] = "IaC"; iac.append(f)

    # Dedup
    sast = dedup_findings(sast)
    sca  = dedup_findings(sca)
    iac  = dedup_findings(iac)

    # Contagens por tipo
    counts_by_type: Dict[str, Dict[str,int]] = {}
    def bump_counts(bucket: str, items: List[Dict]):
        counts_by_type[bucket] = {s:0 for s in SEVERITIES}
        for it in items:
            s = it.get("severity","")
            if s in counts_by_type[bucket]:
                counts_by_type[bucket][s] += 1

    if sast: bump_counts("SAST", sast)
    if sca:  bump_counts("SCA", sca)
    if iac:  bump_counts("IaC", iac)

    # KPIs
    total_sast = sum(counts_by_type.get("SAST", {}).values())
    total_sca  = sum(counts_by_type.get("SCA",  {}).values())
    total_iac  = sum(counts_by_type.get("IaC",  {}).values())
    total_all  = total_sast + total_sca + total_iac
    crit_high  = (counts_by_type.get("SAST", {}).get("CRITICAL",0) + counts_by_type.get("SAST", {}).get("HIGH",0) +
                  counts_by_type.get("SCA",  {}).get("CRITICAL",0) + counts_by_type.get("SCA",  {}).get("HIGH",0) +
                  counts_by_type.get("IaC",  {}).get("CRITICAL",0) + counts_by_type.get("IaC",  {}).get("HIGH",0))

    flow.append(Paragraph("Resumo executivo", styles["H2"]))
    flow.append(Paragraph(
        f"Total de achados: <b>{total_all}</b> (SAST={total_sast}, SCA={total_sca}, IaC={total_iac}). "
        f"CRITICAL+HIGH: <b>{crit_high}</b> (indicadores prioritários de remediação).", styles["Body"]
    ))
    flow.append(Spacer(1, 10))

    # Charts
    overall_chart = os.path.join(CHART_DIR, "overall_by_severity.png")
    bytype_chart  = os.path.join(CHART_DIR, "by_type_severity.png")
    if counts_by_type:
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
    def make_heading(text: str, level: int, styles=styles) -> Paragraph:
        style_name = "H1" if level == 1 else "H2"
        p = Paragraph(text, styles[style_name])
        p.toc_level = level; p.toc_text = text
        return p

    flow.append(make_heading("Sumário", 1))
    flow.append(doc._toc)
    flow.append(PageBreak())

    # ---------- Seções ----------
    def add_type_section(title: str, items: List[Dict]):
        if not items:
            return
        flow.append(make_heading(title, 1))
        for sev in SEVERITIES:
            subset = [f for f in items if f.get("severity")==sev]
            if not subset:
                continue
            flow.append(make_heading(f"{title} — {sev}", 2))
            subset.sort(key=lambda x: (x.get("location",""), x.get("rule_id","")))
            bullets = [bullet_for_finding(styles, title.split(" — ")[0], it.get("rule_id"), it.get("severity"),
                                          it.get("location"), it.get("message")) for it in subset]
            flow.append(ListFlowable(bullets, bulletType="bullet"))
            flow.append(Spacer(1, 8))
        flow.append(PageBreak())

    add_type_section(f"SCA — {sum(counts_by_type.get('SCA',{}).values())} achados", sca)
    add_type_section(f"SAST — {sum(counts_by_type.get('SAST',{}).values())} achados", sast)
    if iac:
        flow.append(make_heading(f"IaC — {sum(counts_by_type.get('IaC',{}).values())} achados", 1))
        for sev in SEVERITIES:
            subset = [f for f in iac if f.get("severity")==sev]
            if not subset:
                continue
            flow.append(make_heading(f"IaC — {sev}", 2))
            subset.sort(key=lambda x: (x.get("location",""), x.get("rule_id","")))
            bullets = [bullet_for_finding(styles, "IaC", it.get("rule_id"), it.get("severity"),
                                          it.get("location"), it.get("message")) for it in subset]
            flow.append(ListFlowable(bullets, bulletType="bullet"))
            flow.append(Spacer(1, 8))

    doc.build(flow)

def main():
    build_pdf()
    print(f"[report] PDF gerado: {REPORT_PATH}")

if __name__ == "__main__":
    main()
