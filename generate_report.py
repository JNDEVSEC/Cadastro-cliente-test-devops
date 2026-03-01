#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, String, Rect
# REMOVIDO: from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics import renderPDF
from reportlab.lib.units import mm
from datetime import datetime, timezone
import json, os
from math import isfinite

# ========== Mescla TOC + conteúdo ==========
try:
    from PyPDF2 import PdfReader, PdfWriter
except Exception:
    PdfReader = None
    PdfWriter = None

# ========== CONFIG EXECUTIVA & TEMA ==========
ORG_NAME = "Sua Empresa"
TITLE    = "Relatório Executivo de Segurança"
# Corrigido: usar timezone-aware e evitar DeprecationWarning
DATE_STR = datetime.now(timezone.utc).strftime("%d/%m/%Y")

PAGE_W, PAGE_H = A4
MARGIN_L = 18 * mm
MARGIN_R = 18 * mm
MARGIN_T = 18 * mm
MARGIN_B = 16 * mm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

# Tipografia
FONT_XS = 8.5
FONT_S  = 9.0
FONT_M  = 10.0
FONT_L  = 12.0
FONT_H  = 16.0
LINE_H  = 12.0

SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]

# Paleta
SEV_COLORS = {
    "CRITICAL": colors.HexColor("#F50F0F"),  # vermelho
    "HIGH":     colors.HexColor("#ea580c"),      # laranja escuro
    "MEDIUM":   colors.HexColor("#f97316"),      # laranja médio
    "LOW":      colors.HexColor("#fed7aa"),      # laranja claro
    "UNKNOWN":  colors.Color(0.60, 0.60, 0.60),  # cinza
}
ORANGE_PRIMARY  = colors.HexColor("#f97316")
ORANGE_DARK     = colors.HexColor("#ea580c")
ORANGE_LIGHT_BG = colors.HexColor("#fff7ed")

# =========================================================
# UTILITÁRIAS
# =========================================================
def wrap_lines(c, text, width, font="Helvetica", size=FONT_S):
    """
    Quebra em múltiplas linhas respeitando largura.
    - Se a palavra for maior que a largura, faz 'hard wrap' por caracteres.
    """
    c.setFont(font, size)
    text = (text or "").strip()
    if not text:
        return [""]

    lines = []
    current = ""

    def flush_current():
        nonlocal current
        if current:
            lines.append(current.rstrip())
            current = ""

    for word in text.split():
        if c.stringWidth(word, font, size) <= width:
            # cabe como palavra; tenta juntar ao 'current'
            test = (current + " " + word).strip()
            if c.stringWidth(test, font, size) <= width:
                current = test
            else:
                flush_current()
                current = word
        else:
            # palavra maior que a largura → quebra “hard”
            if current:
                flush_current()
            chunk = ""
            for ch in word:
                test = chunk + ch
                if c.stringWidth(test, font, size) <= width:
                    chunk = test
                else:
                    if chunk:
                        lines.append(chunk)
                    chunk = ch
            if chunk:
                current = chunk  # último pedaço vira início da próxima linha

    flush_current()
    return lines

def draw_bullet_paragraph(c, x, y, text, max_width, bullet="• ", font="Helvetica", size=FONT_S):
    """
    Desenha um parágrafo com bullet:
      - Primeira linha começa em x com '• '
      - Linhas seguintes alinham após o bullet (indentação)
      - Retorna a nova coordenada y após o parágrafo
    """
    c.setFont(font, size)
    bullet_w = c.stringWidth(bullet, font, size)

    # quebra o texto já descontando a largura do bullet
    lines = wrap_lines(c, text, max_width - bullet_w, font=font, size=size)

    # primeira linha com bullet
    c.drawString(x, y, bullet + (lines[0] if lines else ""))
    y -= LINE_H

    # linhas subsequentes alinhadas após o bullet
    cont_x = x + bullet_w
    for ln in lines[1:]:
        c.drawString(cont_x, y, ln)
        y -= LINE_H

    return y

def clamp_lines(c, lines, width, max_lines, font="Helvetica", size=FONT_S):
    if len(lines) <= max_lines:
        return lines
    c.setFont(font, size)
    trimmed = lines[:max_lines]
    last = trimmed[-1]
    ell = "…"
    while last and c.stringWidth(last + ell, font, size) > width:
        last = last[:-1]
    trimmed[-1] = (last + ell) if last else ell
    return trimmed

def count_by_severity(items, key="severity"):
    counts = {s:0 for s in SEV_ORDER}
    for it in items:
        sev = (it.get(key) or "UNKNOWN").upper()
        if sev not in counts: sev = "UNKNOWN"
        counts[sev] += 1
    return counts

# =========================================================
# CARREGAMENTO DE DADOS
# =========================================================
def load_semgrep_rich():
    """
    Lê semgrep.json (rico) para ter message/fix/references.
    Campos usados:
      - check_id (nome da vulnerabilidade/regra)
      - path, start.line
      - extra.severity, extra.message, extra.fix (opcional),
        extra.metadata.references (lista, opcional)
    """
    if not os.path.exists("semgrep.json"):
        return []
    try:
        data = json.load(open("semgrep.json", "r", encoding="utf-8"))
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta  = extra.get("metadata", {}) or {}
        out.append({
            "rule_id":  r.get("check_id",""),
            "file":     r.get("path",""),
            "line":     (r.get("start",{}) or {}).get("line",""),
            "severity": (extra.get("severity","") or "UNKNOWN").upper(),
            "message":  extra.get("message",""),
            "fix":      extra.get("fix") or meta.get("fix"),
            "references": meta.get("references", []) or meta.get("refs", [])
        })
    return out

def extract_cvss_score_from_dict(cvss_dict):
    if not isinstance(cvss_dict, dict):
        return None
    best = None
    for _, vals in cvss_dict.items():
        if not isinstance(vals, dict):
            continue
        for k in ("V4Score","V4","V4.0","V31Score","V3.1","V3Score","V3","Score","BaseScore"):
            try:
                v = float(vals.get(k))
            except Exception:
                v = None
            if v is not None and (best is None or v > best):
                best = v
    return best

def approx_score_from_severity(sev):
    return {
        "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.0, "UNKNOWN": 0.1
    }.get((sev or "UNKNOWN").upper(), 0.1)

def load_trivy_rich():
    """
    Lê trivy-results.json (rico) para ter Title, Description, URLs, CVSS etc.
    Campos usados:
      - VulnerabilityID, Title, Description, Severity
      - PkgName, InstalledVersion, FixedVersion
      - CVSS (dict) → score prioritizando v4.0
      - PrimaryURL, References
    """
    if not os.path.exists("trivy-results.json"):
        return []
    try:
        tri = json.load(open("trivy-results.json", "r", encoding="utf-8"))
    except Exception:
        return []
    out = []
    for res in tri.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            score = extract_cvss_score_from_dict(v.get("CVSS")) or approx_score_from_severity(sev)
            refs  = v.get("References") or []
            url   = v.get("PrimaryURL") or (refs[0] if refs else None)
            out.append({
                "id": v.get("VulnerabilityID",""),
                "title": v.get("Title") or "",
                "description": v.get("Description") or "",
                "severity": sev,
                "pkg": v.get("PkgName",""),
                "installed": v.get("InstalledVersion",""),
                "fixed": v.get("FixedVersion") or "-",
                "cvss": score,
                "url": url
            })
    return out

# =========================================================
# CAPA / TÍTULOS / RODAPÉ
# =========================================================
def draw_cover(c):
    c.setFillColor(ORANGE_DARK); c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 30)
    c.drawString(MARGIN_L, PAGE_H - 58*mm, TITLE)
    c.setFont("Helvetica", 16); c.drawString(MARGIN_L, PAGE_H - 72*mm, f"Empresa: {ORG_NAME}")
    c.setFont("Helvetica", 12); c.drawString(MARGIN_L, PAGE_H - 84*mm, f"Gerado em: {DATE_STR}")
    c.setFillColor(ORANGE_PRIMARY); c.rect(0, 0, PAGE_W, 9*mm, fill=1, stroke=0)
    c.showPage()

def draw_section_title(c, text, y):
    c.setFillColor(ORANGE_LIGHT_BG)
    c.rect(MARGIN_L-10, y-8, CONTENT_W+20, 24, fill=1, stroke=0)
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold", FONT_H)
    c.drawString(MARGIN_L, y, text)
    return y - 24

def draw_footer(c):
    page = c.getPageNumber()
    c.setFont("Helvetica", 8.5); c.setFillColor(colors.grey)
    c.drawRightString(PAGE_W - MARGIN_R, MARGIN_B - 5, f"Página {page}")
    c.setFillColor(colors.black)

# =========================================================
# GRÁFICOS
# =========================================================

def draw_bars_with_values(c, sem_counts, tri_counts, title, origin_x, origin_y):
    c.setFont("Helvetica-Bold", FONT_L); c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + 210, title)

    d = Drawing(400, 210)
    bar = VerticalBarChart()
    bar.x, bar.y = 36, 32
    bar.width, bar.height = 300, 150
    A = [sem_counts[s] for s in SEV_ORDER]
    B = [tri_counts[s] for s in SEV_ORDER]
    bar.data = [A, B]; bar.categoryAxis.categoryNames = SEV_ORDER
    bar.groupSpacing = 6; bar.barSpacing = 1.5
    bar.bars[0].fillColor = ORANGE_DARK; bar.bars[1].fillColor = ORANGE_PRIMARY
    bar.barLabelFormat = '%0.0f'; bar.barLabels.nudge = 5
    bar.barLabels.fontName = "Helvetica"; bar.barLabels.fontSize = FONT_S
    bar.valueAxis.valueMin = 0; bar.valueAxis.labelTextFormat = '%d'
    d.add(bar)
    leg = Legend(); leg.x, leg.y = 265, 190; leg.fontName="Helvetica"; leg.fontSize=FONT_S
    leg.alignment='right'; leg.colorNamePairs=[(ORANGE_DARK,"Semgrep"),(ORANGE_PRIMARY,"Trivy")]
    d.add(leg)
    renderPDF.draw(d, c, origin_x, origin_y)

def draw_heatmap(c, sem_counts, tri_counts, title, origin_x, origin_y):
    c.setFont("Helvetica-Bold", FONT_L); c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + 150, title)

    grid_w, grid_h = 340, 110
    cell_w = grid_w / len(SEV_ORDER); cell_h = grid_h / 2
    d = Drawing(grid_w, grid_h)

    max_val = max([*sem_counts.values(), *tri_counts.values(), 1])
    SEV_HEAT_TARGET = {
        "CRITICAL": colors.HexColor("#F50F0F"),
        "HIGH":     ORANGE_DARK,
        "MEDIUM":   ORANGE_PRIMARY,
        "LOW":      colors.HexColor("#fed7aa"),
        "UNKNOWN":  colors.Color(0.70, 0.70, 0.70),
    }

    for r, src in enumerate(["Semgrep","Trivy"]):
        for c_idx, sev in enumerate(SEV_ORDER):
            v = sem_counts[sev] if r == 0 else tri_counts[sev]
            intensity = (v / max_val) if max_val else 0.0
            base = colors.white; mix = SEV_HEAT_TARGET[sev]
            fill = colors.Color(
                base.red   + (mix.red   - base.red)   * intensity,
                base.green + (mix.green - base.green) * intensity,
                base.blue  + (mix.blue  - base.blue)  * intensity
            )
            x = c_idx * cell_w; y = (1 - r) * cell_h
            rect = Rect(x, y, cell_w - 3, cell_h - 3, strokeWidth=0.2,
                        strokeColor=colors.lightgrey, fillColor=fill)
            d.add(rect)
            label_color = colors.white if intensity >= 0.60 else colors.black
            d.add(String(x + cell_w/2 - 6, y + cell_h/2 - 5, str(v),
                         fontName="Helvetica", fontSize=FONT_S, fillColor=label_color))

    renderPDF.draw(d, c, origin_x, origin_y)

# =========================================================
# RISCO & CVSS
# =========================================================
def avg_cvss(trivy):
    scores = [v.get("cvss") for v in trivy if isinstance(v.get("cvss"), (int,float))]
    scores = [s for s in scores if s is not None and isfinite(s)]
    return (sum(scores)/len(scores)) if scores else None

# =========================================================
# TÓPICOS (Semgrep & Trivy)
# =========================================================
def draw_topic(c, y, heading, items, color=None):
    """
    Desenha um tópico:
      heading = string (será quebrada em múltiplas linhas)
      items   = lista de strings (cada uma vira um bullet com wrap e indent)
      color   = cor do badge (opcional)
    Faz quebra de página quando necessário.
    """
    # 1) Quebra do heading por largura
    heading_lines = wrap_lines(c, heading, CONTENT_W - 20, font="Helvetica-Bold", size=FONT_M)
    heading_height = len(heading_lines) * LINE_H + 8  # 8 de respiro

    # 2) Altura estimada dos bullets (conservadora)
    bullets_est_h = max(LINE_H * 2 * len(items), LINE_H * len(items)) + 8

    need_h = heading_height + bullets_est_h + 12  # margem extra
    if y - need_h < MARGIN_B + 10:
        draw_footer(c)
        c.showPage()
        y = PAGE_H - MARGIN_T

    # 3) Badge opcional à esquerda do heading
    x = MARGIN_L
    if color:
        c.setFillColor(color)
        c.roundRect(x, y-14, 10, 10, 2.5, fill=1, stroke=0)
        x += 16

    # 4) Desenha o heading (todas as linhas)
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", FONT_M)
    for hl in heading_lines:
        c.drawString(x, y, hl)
        y -= LINE_H
    y -= 4  # pequeno respiro

    # 5) Desenha os bullets (com wrap e indentação correta)
    for ln in items:
        if y - (LINE_H * 2) < MARGIN_B + 8:
            draw_footer(c)
            c.showPage()
            y = PAGE_H - MARGIN_T
            c.setFont("Helvetica", FONT_S)
        y = draw_bullet_paragraph(
            c, x=MARGIN_L + 10, y=y,
            text=ln, max_width=CONTENT_W - 20,
            bullet="• ", font="Helvetica", size=FONT_S
        )
    y -= 6
    return y

def draw_semgrep_topics(c, semgrep):
    """
    Para cada achado do Semgrep:
      Heading: [SEV] <check_id>
      Itens:
        - Arquivo: <path>:<line>
        - Risco:   <extra.message>
        - Sugestão: <extra.fix> (se houver) ou orientação genérica
        - Referências: primeira(s) URLs
    """
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Vulnerabilidades – SAST", y)
    for r in semgrep:
        sev = (r.get("severity") or "UNKNOWN").upper()
        heading = f"[{sev}] {r.get('rule_id','')}".strip()
        arquivo = f"Arquivo: {r.get('file','')}:{r.get('line','')}".strip(":")
        risco   = f"Risco: {r.get('message','')}" if r.get("message") else "Risco: (não informado pela regra)"
        fix     = r.get("fix")
        if fix:
            sugestao = f"Sugestão: {fix}"
        else:
            sugestao = "Sugestão: aplicar mitigação recomendada pela regra; revisar input validation, autenticação/controle de acesso e padrões seguros."
        refs = r.get("references") or []
        ref_line = f"Referências: {', '.join(refs[:2])}" if refs else None

        lines = [arquivo, risco, sugestao]
        if ref_line: lines.append(ref_line)
        y = draw_topic(c, y, heading, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()

def draw_trivy_topics(c, vulns):
    """
    Para cada vulnerabilidade de SCA:
      Heading: [SEV] <VulnerabilityID> — <Title>
      Itens:
        - Pacote: <PkgName> (<Installed> -> <Fixed>)
        - CVSS: <score>
        - Risco: <Description> (wrap completo)
        - Sugestão: atualizar para <Fixed> (se disponível)
        - Referência: <PrimaryURL/References[0]>
    """
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Vulnerabilidades – SCA", y)
    for v in vulns:
        sev   = (v.get("severity") or "UNKNOWN").upper()
        vid   = v.get("id","")
        title = v.get("title") or ""
        head  = f"[{sev}] {vid}" + (f" — {title}" if title else "")
        pkg   = v.get("pkg","")
        inst  = v.get("installed","")
        fix   = v.get("fixed","-")

        l_pkg  = f"Pacote: {pkg} ({inst} -> {fix})" if (pkg or inst) else None
        l_cvss = f"CVSS: {v['cvss']:.1f}" if isinstance(v.get("cvss"), (int,float)) else None
        desc   = (v.get("description") or "").strip()
        l_risk = "Risco: " + (desc if desc else "(sem descrição do fornecedor)")
        l_fix  = f"Sugestão: atualizar para {fix}" if fix and fix != "-" else "Sugestão: verificar boletins do fornecedor / aplicar patch assim que disponível."
        url    = v.get("url")
        l_ref  = f"Referência: {url}" if url else None

        lines = [ln for ln in [l_pkg, l_cvss, l_risk, l_fix, l_ref] if ln]
        y = draw_topic(c, y, head, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()

# =========================================================
# SUMÁRIO (TOC)
# =========================================================
def build_toc_pdf(toc_items, outfile="toc.pdf"):
    c = canvas.Canvas(outfile, pagesize=A4)
    y = PAGE_H - MARGIN_T
    c.setFont("Helvetica-Bold", 18); c.drawString(MARGIN_L, y, "Sumário")
    y -= 20; c.setLineWidth(0.7); c.setStrokeColor(colors.HexColor("#e5e7eb"))
    c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
    y -= 14; c.setFont("Helvetica", FONT_M)
    for title, page in toc_items:
        c.drawString(MARGIN_L, y, title)
        c.drawRightString(MARGIN_L + CONTENT_W, y, str(page))
        y -= 14
        if y < MARGIN_B + 16:
            c.showPage()
            y = PAGE_H - MARGIN_T
            c.setFont("Helvetica-Bold", 18); c.drawString(MARGIN_L, y, "Sumário (cont.)")
            y -= 20; c.setLineWidth(0.7); c.setStrokeColor(colors.HexColor("#e5e7eb"))
            c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
            y -= 14; c.setFont("Helvetica", FONT_M)
    c.save()

def merge_cover_toc_content(content_path="content.pdf", toc_path="toc.pdf", out_path="security-report.pdf"):
    if PdfReader is None or PdfWriter is None:
        try: os.replace(content_path, out_path)
        except Exception: pass
        return
    reader = PdfReader(content_path); writer = PdfWriter()
    writer.add_page(reader.pages[0])  # capa
    toc_reader = PdfReader(toc_path)
    for p in toc_reader.pages: writer.add_page(p)
    for i in range(1, len(reader.pages)): writer.add_page(reader.pages[i])
    with open(out_path, "wb") as f: writer.write(f)

# =========================================================
# PRINCIPAL
# =========================================================
def main():
    # Dados
    semgrep = load_semgrep_rich()
    trivy   = load_trivy_rich()
    semgrep_counts = count_by_severity(semgrep, key="severity")
    trivy_counts   = count_by_severity(trivy,   key="severity")

    # CONTENT (capa + resumo + gráficos + tópicos)
    section_pages = {}
    c = canvas.Canvas("content.pdf", pagesize=A4)

    # Capa
    draw_cover(c)  # próxima página será 2

    # Resumo Executivo
    section_pages["Resumo Executivo"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Resumo Executivo", y)

    # Métricas resumo
    c.setFont("Helvetica-Bold", FONT_M)
    risks = {
        "Risco Imediato (CRITICAL)": semgrep_counts["CRITICAL"] + trivy_counts["CRITICAL"],
        "Risco Alto (HIGH)":         semgrep_counts["HIGH"]     + trivy_counts["HIGH"],
        "Risco Médio (MEDIUM)":      semgrep_counts["MEDIUM"]   + trivy_counts["MEDIUM"],
        "Monitoramento (LOW/UNKNOWN)": (semgrep_counts["LOW"] + semgrep_counts["UNKNOWN"] +
                                        trivy_counts["LOW"]   + trivy_counts["UNKNOWN"])
    }
    for label, val in risks.items():
        if "CRITICAL" in label: c.setFillColor(SEV_COLORS["CRITICAL"])
        elif "HIGH" in label:   c.setFillColor(SEV_COLORS["HIGH"])
        elif "MEDIUM" in label: c.setFillColor(SEV_COLORS["MEDIUM"])
        else:                    c.setFillColor(SEV_COLORS["LOW"])
        c.drawString(MARGIN_L, y, f"{label}: {val}")
        y -= 14
    c.setFillColor(colors.black)

    avg = avg_cvss(trivy)
    y -= 6; c.setFont("Helvetica", FONT_M)
    c.drawString(MARGIN_L, y, f"CVSS médio (prioridade 4.0; fallback 3.x / nível): {avg:.1f}" if avg is not None else "CVSS médio: N/A")
    y -= 12

    draw_heatmap(c, semgrep_counts, trivy_counts, "Heatmap de Severidade (Semgrep × Trivy)", MARGIN_L, y - 150)
    draw_footer(c); c.showPage()

    # Gráficos (somente barras + heatmap, sem pizza)
    section_pages["Visão Geral – Gráficos"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Visão Geral – Gráficos", y)
    y -= 14
    # REMOVIDO: draw_pie_with_values(...)
    # Em vez de pizza, mantemos apenas o comparativo SAST × SCA
    draw_bars_with_values(c, semgrep_counts, trivy_counts, "SAST × SCA por Severidade", MARGIN_L, y - 220)
    draw_footer(c); c.showPage()

    # Semgrep em tópicos
    section_pages["Vulnerabilidades – SAST"] = c.getPageNumber()
    draw_semgrep_topics(c, semgrep)

    # Trivy em tópicos
    section_pages["Vulnerabilidades – SCA"] = c.getPageNumber()
    draw_trivy_topics(c, trivy)

    c.save()

    # TOC (ajuste +1 página por inserir o TOC após capa)
    toc_items = []
    for name, p in section_pages.items():
        final_page = p + 1 if p >= 2 else p
        toc_items.append((name, final_page))
    build_toc_pdf(toc_items, "toc.pdf")
    merge_cover_toc_content("content.pdf", "toc.pdf", "security-report.pdf")

    try:
        os.remove("content.pdf"); os.remove("toc.pdf")
    except Exception:
        pass

if __name__ == "__main__":
    main()
