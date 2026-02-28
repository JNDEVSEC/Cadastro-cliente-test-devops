#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, String, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics import renderPDF
from reportlab.lib.units import mm
from datetime import datetime
import json
import os
from math import isfinite

# Mescla TOC + conteúdo
try:
    from PyPDF2 import PdfReader, PdfWriter
except Exception:
    PdfReader = None
    PdfWriter = None

# =========================
# CONFIG EXECUTIVA & TEMA
# =========================
ORG_NAME = "Sua Empresa"
TITLE = "Relatório Executivo de Segurança"
DATE_STR = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")

PAGE_W, PAGE_H = A4
MARGIN_L = 18 * mm
MARGIN_R = 18 * mm
MARGIN_T = 18 * mm
MARGIN_B = 16 * mm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

# Tipografia (mais enxuta)
FONT_S  = 9          # corpo da tabela
FONT_M  = 10         # rótulos/legendas
FONT_L  = 12         # subtítulos
FONT_H  = 16         # títulos de seção
LINE_H  = 12         # altura de linha base
ROW_PAD_Y = 3        # padding vertical por linha

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Paleta laranja
SEV_COLORS = {
    "CRITICAL": colors.Color(0.85, 0.10, 0.10),        # vermelho para crítico
    "HIGH":     colors.HexColor("#ea580c"),            # laranja escuro
    "MEDIUM":   colors.HexColor("#f97316"),            # laranja médio
    "LOW":      colors.HexColor("#fed7aa"),            # laranja claro
    "UNKNOWN":  colors.Color(0.60, 0.60, 0.60),        # cinza
}
ORANGE_PRIMARY   = colors.HexColor("#f97316")
ORANGE_DARK      = colors.HexColor("#ea580c")
ORANGE_LIGHT_BG  = colors.HexColor("#fff7ed")          # faixa de título
ZEBRA_BG         = colors.HexColor("#fff1e6")          # zebra

# ============ LARGURAS DE TABELAS (SEPARADAS) ============
# --- Semgrep: Sev | Origem | Linha | Detalhe
COLW_SMG_SEV   = 58
COLW_SMG_ORIG  = 150
COLW_SMG_LINE  = 48
COLW_SMG_DET   = CONTENT_W - COLW_SMG_SEV - COLW_SMG_ORIG - COLW_SMG_LINE - 10  # respiro

# --- Trivy: Sev | Origem | Detalhe
COLW_TRV_SEV   = 58
COLW_TRV_ORIG  = 180
COLW_TRV_DET   = CONTENT_W - COLW_TRV_SEV - COLW_TRV_ORIG - 8

# Limites (para caber bem na página)
MAX_ROWS_SEMGREP = 120
MAX_ROWS_TRIVY   = 120
MAX_LINES_ORIG   = 2      # origem: até 2 linhas
MAX_LINES_DET    = 3      # detalhe: até 3 linhas

# =========================
# UTILITÁRIAS
# =========================
def wrap_lines(c, text, width, font="Helvetica", size=FONT_S):
    """Quebra em múltiplas linhas respeitando largura."""
    c.setFont(font, size)
    words = (text or "").split()
    if not words:
        return [""]
    lines, line = [], ""
    for w in words:
        test = (line + " " + w).strip()
        if c.stringWidth(test, font, size) <= width:
            line = test
        else:
            if line:
                lines.append(line)
            line = w
    if line:
        lines.append(line)
    return lines

def clamp_lines_to_fit(c, lines, width, max_lines, font="Helvetica", size=FONT_S):
    """Limita nº de linhas; aplica reticências (…) na última, se necessário."""
    if len(lines) <= max_lines:
        return lines
    trimmed = lines[:max_lines]
    last = trimmed[-1]
    c.setFont(font, size)
    ell = "…"
    # Encurta até caber com “…” no final
    while last and c.stringWidth(last + ell, font, size) > width:
        last = last[:-1]
    trimmed[-1] = (last + ell) if last else ell
    return trimmed

def count_by_severity(items, key="severity"):
    counts = {s: 0 for s in SEV_ORDER}
    for it in items:
        sev = (it.get(key) or "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1
    return counts

def load_semgrep():
    if not os.path.exists("semgrep.report.json"):
        return []
    try:
        data = json.load(open("semgrep.report.json"))
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        out.append({
            "severity": (r.get("severity") or "UNKNOWN").upper(),
            "file": r.get("file", ""),
            "line": r.get("line", ""),
            "message": r.get("message", "")
        })
    return out

def extract_cvss_score_from_dict(cvss_dict):
    """CVSS prioridade 4.0, fallback 3.x / Score genérico."""
    if not isinstance(cvss_dict, dict):
        return None
    best = None
    for _, vals in cvss_dict.items():
        if not isinstance(vals, dict):
            continue
        for key in ("V4Score","V4","V4.0","V31Score","V3.1","V3Score","V3","Score","BaseScore"):
            try:
                v = float(vals.get(key))
            except Exception:
                v = None
            if v is not None and (best is None or v > best):
                best = v
    return best

def approx_score_from_severity(sev):
    return {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.5,
        "LOW": 2.0,
        "UNKNOWN": 0.1
    }.get((sev or "UNKNOWN").upper(), 0.1)

def load_trivy():
    if not os.path.exists("trivy-results.json"):
        return []
    try:
        tri = json.load(open("trivy-results.json"))
    except Exception:
        return []
    out = []
    for res in tri.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            cvss = v.get("CVSS")
            score = extract_cvss_score_from_dict(cvss) if cvss else None
            if score is None:
                score = approx_score_from_severity(sev)
            out.append({
                "severity": sev,
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion") or "-",
                "cvss": score
            })
    return out

# =========================
# CAPA
# =========================
def draw_cover(c):
    c.setFillColor(ORANGE_DARK)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 30)
    c.drawString(MARGIN_L, PAGE_H - 58*mm, TITLE)
    c.setFont("Helvetica", 16)
    c.drawString(MARGIN_L, PAGE_H - 72*mm, f"Empresa: {ORG_NAME}")
    c.setFont("Helvetica", 12)
    c.drawString(MARGIN_L, PAGE_H - 84*mm, f"Gerado em: {DATE_STR}")
    c.setFillColor(ORANGE_PRIMARY)
    c.rect(0, 0, PAGE_W, 9*mm, fill=1, stroke=0)
    c.showPage()

# =========================
# TÍTULOS / RODAPÉ
# =========================
def draw_section_title(c, text, y):
    c.setFillColor(ORANGE_LIGHT_BG)
    c.rect(MARGIN_L-10, y-8, CONTENT_W+20, 24, fill=1, stroke=0)
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", FONT_H)
    c.drawString(MARGIN_L, y, text)
    return y - 24

def draw_footer(c):
    page = c.getPageNumber()
    c.setFont("Helvetica", 8.5)
    c.setFillColor(colors.grey)
    c.drawRightString(PAGE_W - MARGIN_R, MARGIN_B - 5, f"Página {page}")
    c.setFillColor(colors.black)

# =========================
# GRÁFICOS (pizza + barras + heatmap)
# =========================
def draw_pie_with_values(c, counts, title, origin_x, origin_y):
    """Desenha o gráfico de pizza com rótulos (valor e %) e título no canvas."""
    total = sum(counts.values()) or 1

    # Título (no canvas) um pouco acima do desenho
    c.setFont("Helvetica-Bold", FONT_L)
    c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + 230, title)

    d = Drawing(360, 220)
    pie = Pie()
    pie.x = 26
    pie.y = 10
    pie.width  = 205
    pie.height = 205
    pie.data   = [counts[s] for s in SEV_ORDER]
    pie.labels = [f"{s} {counts[s]} ({(counts[s]/total*100):.0f}%)" for s in SEV_ORDER]
    pie.sideLabels = True
    pie.slices.strokeWidth = 0.3
    for i, s in enumerate(SEV_ORDER):
        pie.slices[i].fillColor = SEV_COLORS[s]

    d.add(pie)
    renderPDF.draw(d, c, origin_x, origin_y)

def draw_bars_with_values(c, sem_counts, tri_counts, title, origin_x, origin_y):
    """Barras com rótulos numéricos, legenda e título no canvas."""
    c.setFont("Helvetica-Bold", FONT_L)
    c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + 210, title)

    d = Drawing(400, 210)
    bar = VerticalBarChart()
    bar.x = 36
    bar.y = 32
    bar.width  = 300
    bar.height = 150

    A = [sem_counts[s] for s in SEV_ORDER]
    B = [tri_counts[s] for s in SEV_ORDER]
    bar.data = [A, B]
    bar.categoryAxis.categoryNames = SEV_ORDER
    bar.groupSpacing = 6
    bar.barSpacing   = 1.5

    bar.bars[0].fillColor = ORANGE_DARK
    bar.bars[1].fillColor = ORANGE_PRIMARY
    bar.barLabelFormat = '%0.0f'
    bar.barLabels.nudge = 5
    bar.barLabels.fontName = "Helvetica"
    bar.barLabels.fontSize = FONT_S

    bar.valueAxis.valueMin = 0
    bar.valueAxis.labelTextFormat = '%d'
    d.add(bar)

    leg = Legend()
    leg.x = 265
    leg.y = 190
    leg.fontName = "Helvetica"
    leg.fontSize = FONT_S
    leg.alignment = 'right'
    leg.colorNamePairs = [(ORANGE_DARK, "Semgrep"), (ORANGE_PRIMARY, "Trivy")]
    d.add(leg)

    renderPDF.draw(d, c, origin_x, origin_y)

def draw_heatmap(c, sem_counts, tri_counts, title, origin_x, origin_y):
    """
    Heatmap 2 x 5 (linhas: Semgrep, Trivy; colunas: severidades).
    Cor-alvo por severidade: CRITICAL=vermelho, HIGH=laranja escuro, etc.
    A intensidade mistura branco -> cor-alvo conforme o volume relativo.
    """
    # Título no canvas
    c.setFont("Helvetica-Bold", FONT_L)
    c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + 150, title)

    grid_w, grid_h = 340, 110
    cell_w = grid_w / len(SEV_ORDER)
    cell_h = grid_h / 2
    d = Drawing(grid_w, grid_h)

    max_val = max([*sem_counts.values(), *tri_counts.values(), 1])

    # alvo de cor por severidade (CRITICAL = vermelho de fato)
    SEV_HEAT_TARGET = {
        "CRITICAL": colors.Color(0.85, 0.10, 0.10),
        "HIGH":     ORANGE_DARK,
        "MEDIUM":   ORANGE_PRIMARY,
        "LOW":      colors.HexColor("#fed7aa"),
        "UNKNOWN":  colors.Color(0.70, 0.70, 0.70),
    }

    for r, src in enumerate(["Semgrep", "Trivy"]):
        for c_idx, sev in enumerate(SEV_ORDER):
            v = sem_counts[sev] if r == 0 else tri_counts[sev]
            intensity = (v / max_val) if max_val else 0.0
            base = colors.white
            mix  = SEV_HEAT_TARGET[sev]
            fill = colors.Color(
                base.red   + (mix.red   - base.red)   * intensity,
                base.green + (mix.green - base.green) * intensity,
                base.blue  + (mix.blue  - base.blue)  * intensity
            )
            x = c_idx * cell_w
            y = (1 - r) * cell_h
            rect = Rect(x, y, cell_w - 3, cell_h - 3,
                        strokeWidth=0.2, strokeColor=colors.lightgrey, fillColor=fill)
            d.add(rect)

            # Rótulo numérico com contraste automático
            label_color = colors.white if intensity >= 0.60 else colors.black
            d.add(String(x + cell_w/2 - 6, y + cell_h/2 - 5, str(v),
                         fontName="Helvetica", fontSize=FONT_S, fillColor=label_color))

    renderPDF.draw(d, c, origin_x, origin_y)

# =========================
# RISCO & CVSS
# =========================
def risk_markers(sem_counts, tri_counts):
    total = {k: sem_counts.get(k,0) + tri_counts.get(k,0) for k in SEV_ORDER}
    return {
        "imediato": total["CRITICAL"],
        "alto":     total["HIGH"],
        "medio":    total["MEDIUM"],
        "monitor":  total["LOW"] + total["UNKNOWN"]
    }

def avg_cvss(trivy):
    scores = [v.get("cvss") for v in trivy if isinstance(v.get("cvss"), (int,float))]
    scores = [s for s in scores if s is not None and isfinite(s)]
    return (sum(scores)/len(scores)) if scores else None

# =========================
# TABELAS — SEMGREP (Sev|Origem|Linha|Detalhe)
# =========================
def draw_table_header_semgrep(c, y):
    c.setFillColor(ORANGE_PRIMARY)
    c.rect(MARGIN_L, y-15, CONTENT_W, 17, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", FONT_M)
    c.drawString(MARGIN_L + 6, y-4, "Sev")
    c.drawString(MARGIN_L + COLW_SMG_SEV + 6, y-4, "Origem")
    c.drawString(MARGIN_L + COLW_SMG_SEV + COLW_SMG_ORIG + 6, y-4, "Linha")
    c.drawString(MARGIN_L + COLW_SMG_SEV + COLW_SMG_ORIG + COLW_SMG_LINE + 6, y-4, "Detalhe")
    c.setFillColor(colors.black)
    return y - 21

def draw_table_rows_semgrep(c, items, start_y):
    y = start_y
    c.setFont("Helvetica", FONT_S)

    for idx, it in enumerate(items):
        sev   = (it.get("severity") or "UNKNOWN").upper()
        origem_txt = it.get("file", "")
        linha_txt  = str(it.get("line", ""))
        detalhe_txt = it.get("message", "")

        # Quebras por coluna
        org_lines = wrap_lines(c, origem_txt, COLW_SMG_ORIG - 12, size=FONT_S)
        det_lines = wrap_lines(c, detalhe_txt, COLW_SMG_DET  - 12, size=FONT_S)
        org_lines = clamp_lines_to_fit(c, org_lines, COLW_SMG_ORIG - 12, MAX_LINES_ORIG, size=FONT_S)
        det_lines = clamp_lines_to_fit(c, det_lines, COLW_SMG_DET  - 12, MAX_LINES_DET,  size=FONT_S)
        line_lines = [linha_txt]  # 1 linha

        row_lines = max(1, len(org_lines), len(det_lines), len(line_lines))
        row_h = ROW_PAD_Y*2 + row_lines * LINE_H

        # quebra de página
        if y - row_h < MARGIN_B + 8:
            draw_footer(c)
            c.showPage()
            y = PAGE_H - MARGIN_T
            y = draw_table_header_semgrep(c, y)

        # zebra
        if idx % 2 == 0:
            c.setFillColor(ZEBRA_BG)
            c.rect(MARGIN_L, y - row_h, CONTENT_W, row_h, fill=1, stroke=0)
        c.setFillColor(colors.black)

        # Badge severidade
        c.setFillColor(SEV_COLORS.get(sev, colors.black))
        c.roundRect(MARGIN_L + 6, y - ROW_PAD_Y - LINE_H, COLW_SMG_SEV - 12, LINE_H+3, 2.5, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", FONT_S)
        c.drawString(MARGIN_L + 10, y - ROW_PAD_Y - LINE_H + 2, sev)
        c.setFillColor(colors.black)
        c.setFont("Helvetica", FONT_S)

        # Origem
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in org_lines:
            c.drawString(MARGIN_L + COLW_SMG_SEV + 6, tx_y, ln)
            tx_y -= LINE_H

        # Linha (sempre 1)
        c.drawString(MARGIN_L + COLW_SMG_SEV + COLW_SMG_ORIG + 6, y - ROW_PAD_Y - LINE_H + 2, linha_txt)

        # Detalhe
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in det_lines:
            c.drawString(MARGIN_L + COLW_SMG_SEV + COLW_SMG_ORIG + COLW_SMG_LINE + 6, tx_y, ln)
            tx_y -= LINE_H

        y -= row_h

    return y

# =========================
# TABELAS — TRIVY (Sev|Origem|Detalhe)
# =========================
def draw_table_header_trivy(c, y):
    c.setFillColor(ORANGE_PRIMARY)
    c.rect(MARGIN_L, y-15, CONTENT_W, 17, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", FONT_M)
    c.drawString(MARGIN_L + 6, y-4, "Sev")
    c.drawString(MARGIN_L + COLW_TRV_SEV + 6, y-4, "Origem")
    c.drawString(MARGIN_L + COLW_TRV_SEV + COLW_TRV_ORIG + 6, y-4, "Detalhe")
    c.setFillColor(colors.black)
    return y - 21

def draw_table_rows_trivy(c, items, start_y):
    y = start_y
    c.setFont("Helvetica", FONT_S)

    for idx, it in enumerate(items):
        sev = (it.get("severity") or "UNKNOWN").upper()
        origem_txt  = it.get("pkg", "")
        detalhe_txt = f"{it.get('id','')} | {it.get('installed','')} -> {it.get('fixed','')}"
        if it.get("cvss") is not None:
            detalhe_txt += f" | CVSS {it['cvss']:.1f}"

        org_lines = wrap_lines(c, origem_txt,  COLW_TRV_ORIG - 12, size=FONT_S)
        det_lines = wrap_lines(c, detalhe_txt, COLW_TRV_DET  - 12, size=FONT_S)
        org_lines = clamp_lines_to_fit(c, org_lines, COLW_TRV_ORIG - 12, MAX_LINES_ORIG, size=FONT_S)
        det_lines = clamp_lines_to_fit(c, det_lines, COLW_TRV_DET  - 12, MAX_LINES_DET,  size=FONT_S)

        row_lines = max(1, len(org_lines), len(det_lines))
        row_h = ROW_PAD_Y*2 + row_lines * LINE_H

        if y - row_h < MARGIN_B + 8:
            draw_footer(c)
            c.showPage()
            y = PAGE_H - MARGIN_T
            y = draw_table_header_trivy(c, y)

        # zebra
        if idx % 2 == 0:
            c.setFillColor(ZEBRA_BG)
            c.rect(MARGIN_L, y - row_h, CONTENT_W, row_h, fill=1, stroke=0)
        c.setFillColor(colors.black)

        # badge
        c.setFillColor(SEV_COLORS.get(sev, colors.black))
        c.roundRect(MARGIN_L + 6, y - ROW_PAD_Y - LINE_H, COLW_TRV_SEV - 12, LINE_H+3, 2.5, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", FONT_S)
        c.drawString(MARGIN_L + 10, y - ROW_PAD_Y - LINE_H + 2, sev)
        c.setFillColor(colors.black)
        c.setFont("Helvetica", FONT_S)

        # Origem
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in org_lines:
            c.drawString(MARGIN_L + COLW_TRV_SEV + 6, tx_y, ln)
            tx_y -= LINE_H

        # Detalhe
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in det_lines:
            c.drawString(MARGIN_L + COLW_TRV_SEV + COLW_TRV_ORIG + 6, tx_y, ln)
            tx_y -= LINE_H

        y -= row_h

    return y

# =========================
# SUMÁRIO (TOC)
# =========================
def build_toc_pdf(toc_items, outfile="toc.pdf"):
    c = canvas.Canvas(outfile, pagesize=A4)
    y = PAGE_H - MARGIN_T
    c.setFont("Helvetica-Bold", 18)
    c.drawString(MARGIN_L, y, "Sumário")
    y -= 20
    c.setLineWidth(0.7)
    c.setStrokeColor(colors.HexColor("#e5e7eb"))
    c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
    y -= 14
    c.setFont("Helvetica", FONT_M)
    for title, page in toc_items:
        c.drawString(MARGIN_L, y, title)
        c.drawRightString(MARGIN_L + CONTENT_W, y, str(page))
        y -= 14
        if y < MARGIN_B + 16:
            c.showPage()
            y = PAGE_H - MARGIN_T
            c.setFont("Helvetica-Bold", 18)
            c.drawString(MARGIN_L, y, "Sumário (cont.)")
            y -= 20
            c.setLineWidth(0.7)
            c.setStrokeColor(colors.HexColor("#e5e7eb"))
            c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
            y -= 14
            c.setFont("Helvetica", FONT_M)
    c.save()

def merge_cover_toc_content(content_path="content.pdf", toc_path="toc.pdf", out_path="security-report.pdf"):
    if PdfReader is None or PdfWriter is None:
        try:
            os.replace(content_path, out_path)
        except Exception:
            pass
        return
    reader = PdfReader(content_path)
    writer = PdfWriter()
    # Capa (página 1)
    writer.add_page(reader.pages[0])
    # TOC
    toc_reader = PdfReader(toc_path)
    for p in toc_reader.pages:
        writer.add_page(p)
    # Restante do conteúdo
    for i in range(1, len(reader.pages)):
        writer.add_page(reader.pages[i])
    with open(out_path, "wb") as f:
        writer.write(f)

# =========================
# PRINCIPAL
# =========================
def main():
    # Dados
    semgrep = load_semgrep()
    trivy   = load_trivy()
    semgrep_counts = count_by_severity(semgrep)
    trivy_counts   = count_by_severity(trivy)

    # CONTENT (capa + resumo + gráficos + tabelas)
    section_pages = {}
    c = canvas.Canvas("content.pdf", pagesize=A4)

    # Capa
    draw_cover(c)  # próxima página será 2

    # Resumo Executivo
    section_pages["Resumo Executivo"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Resumo Executivo", y)

    # Marcadores de Risco
    risks = {
        "Risco Imediato (CRITICAL)": semgrep_counts["CRITICAL"] + trivy_counts["CRITICAL"],
        "Risco Alto (HIGH)":         semgrep_counts["HIGH"]     + trivy_counts["HIGH"],
        "Risco Médio (MEDIUM)":      semgrep_counts["MEDIUM"]   + trivy_counts["MEDIUM"],
        "Monitoramento (LOW/UNKNOWN)": (semgrep_counts["LOW"] + semgrep_counts["UNKNOWN"] +
                                        trivy_counts["LOW"]   + trivy_counts["UNKNOWN"])
    }
    c.setFont("Helvetica-Bold", FONT_M)
    for label, val in risks.items():
        if "CRITICAL" in label: c.setFillColor(SEV_COLORS["CRITICAL"])
        elif "HIGH" in label:   c.setFillColor(SEV_COLORS["HIGH"])
        elif "MEDIUM" in label: c.setFillColor(SEV_COLORS["MEDIUM"])
        else:                    c.setFillColor(SEV_COLORS["LOW"])
        c.drawString(MARGIN_L, y, f"{label}: {val}")
        y -= 14
    c.setFillColor(colors.black)

    # CVSS médio
    avg = avg_cvss(trivy)
    y -= 6
    c.setFont("Helvetica", FONT_M)
    c.drawString(MARGIN_L, y, f"CVSS médio (prioridade 4.0; fallback 3.x / nível): {avg:.1f}" if avg is not None else "CVSS médio: N/A")
    y -= 12

    # Heatmap
    draw_heatmap(c, semgrep_counts, trivy_counts, "Heatmap de Severidade (Semgrep × Trivy)", MARGIN_L, y - 150)
    draw_footer(c)
    c.showPage()

    # Gráficos (com respiro abaixo do título para não encostar)
    section_pages["Visão Geral – Gráficos"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Visão Geral – Gráficos", y)
    y -= 14  # respiro adicional
    draw_pie_with_values(c, semgrep_counts, "Distribuição por Severidade – Semgrep",
                         MARGIN_L, y - 300)  # aumentei 20px
    draw_bars_with_values(c, semgrep_counts, trivy_counts, "Semgrep × Trivy por Severidade",
                          MARGIN_L, y - 560)
    draw_footer(c)
    c.showPage()

    # Tabela Semgrep (Sev | Origem | Linha | Detalhe)
    section_pages["Tabela de Achados – Semgrep"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Tabela de Achados – Semgrep", y)
    y = draw_table_header_semgrep(c, y)
    y = draw_table_rows_semgrep(c, semgrep[:MAX_ROWS_SEMGREP], y)
    draw_footer(c)
    c.showPage()

    # Tabela Trivy (Sev | Origem | Detalhe)
    section_pages["Tabela de Vulnerabilidades – Trivy"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Tabela de Vulnerabilidades – Trivy", y)
    y = draw_table_header_trivy(c, y)
    y = draw_table_rows_trivy(c, trivy[:MAX_ROWS_TRIVY], y)
    draw_footer(c)
    c.showPage()

    c.save()

    # TOC (ajuste +1 página por inserir o TOC após capa)
    toc_items = []
    for name, p in section_pages.items():
        final_page = p + 1 if p >= 2 else p
        toc_items.append((name, final_page))
    build_toc_pdf(toc_items, "toc.pdf")

    # Merge final
    merge_cover_toc_content("content.pdf", "toc.pdf", "security-report.pdf")

    # limpeza opcional
    try:
        os.remove("content.pdf")
        os.remove("toc.pdf")
    except Exception:
        pass

if __name__ == "__main__":
    main()
