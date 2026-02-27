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

# Para mesclar TOC com o conteúdo
try:
    from PyPDF2 import PdfReader, PdfWriter
except Exception:
    PdfReader = None
    PdfWriter = None

# =============================
# CONFIGURAÇÕES EXECUTIVAS
# =============================
ORG_NAME = "Sua Empresa"
TITLE = "Relatório Executivo de Segurança"
DATE_STR = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")

PAGE_W, PAGE_H = A4
MARGIN_L = 20 * mm
MARGIN_R = 20 * mm
MARGIN_T = 20 * mm
MARGIN_B = 20 * mm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Paleta laranja solicitada
SEV_COLORS = {
    "CRITICAL": colors.Color(0.85, 0.10, 0.10),      # vermelho
    "HIGH":     colors.HexColor("#ea580c"),          # laranja escuro
    "MEDIUM":   colors.HexColor("#f97316"),          # laranja médio
    "LOW":      colors.HexColor("#fed7aa"),          # laranja claro
    "UNKNOWN":  colors.Color(0.60, 0.60, 0.60),      # cinza
}
ORANGE_PRIMARY   = colors.HexColor("#f97316")
ORANGE_DARK      = colors.HexColor("#ea580c")
ORANGE_LIGHT_BG  = colors.HexColor("#fff7ed")        # fundo seção
ZEBRA_BG         = colors.HexColor("#fff1e6")        # zebra de tabela

# Tabela
COL_W_SEV   = 70
COL_W_ORIG  = 180
COL_W_DET   = CONTENT_W - COL_W_SEV - COL_W_ORIG - 10
ROW_PAD_Y   = 4
LINE_H      = 13
MAX_ROWS_SEMGREP = 120
MAX_ROWS_TRIVY   = 120

# =============================
# UTILITÁRIAS
# =============================
def wrap_text(c, text, width, font="Helvetica", size=10):
    """Quebra o texto por largura."""
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
    """Tenta achar CVSS com prioridade V4, depois V3.1, V3 e, por fim, qualquer Score."""
    if not isinstance(cvss_dict, dict):
        return None
    best = None
    # percorre fontes (nvd, redhat, etc.)
    for source, vals in cvss_dict.items():
        if not isinstance(vals, dict):
            continue
        # chaves possíveis (variam por fornecedor)
        for key in ["V4Score", "V4", "V4.0", "V31Score", "V3.1", "V3Score", "V3", "Score", "BaseScore"]:
            v = vals.get(key)
            try:
                v = float(v)
            except Exception:
                v = None
            if v is not None and (best is None or v > best):
                best = v
    return best

def approx_score_from_severity(sev):
    """Fallback: aproximação simples baseada no nível (quando não houver CVSS no JSON)."""
    mapping = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.5,
        "LOW": 2.0,
        "UNKNOWN": 0.1
    }
    return mapping.get((sev or "UNKNOWN").upper(), 0.1)

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
            score = None
            # tenta extrair CVSS (prioriza V4)
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

# =============================
# CAPA
# =============================
def draw_cover(c):
    c.setFillColor(ORANGE_DARK)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 32)
    c.drawString(MARGIN_L, PAGE_H - 60*mm, TITLE)

    c.setFont("Helvetica", 18)
    c.drawString(MARGIN_L, PAGE_H - 75*mm, f"Empresa: {ORG_NAME}")

    c.setFont("Helvetica", 14)
    c.drawString(MARGIN_L, PAGE_H - 90*mm, f"Gerado em: {DATE_STR}")

    c.setFillColor(ORANGE_PRIMARY)
    c.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)

    c.showPage()

# =============================
# TOPOLOGIA SEÇÕES / TÍTULOS / RODAPÉ
# =============================
def draw_section_title(c, text, y):
    c.setFillColor(ORANGE_LIGHT_BG)
    c.rect(MARGIN_L-10, y-8, CONTENT_W+20, 26, fill=1, stroke=0)
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN_L, y, text)
    return y - 26

def draw_footer(c):
    page = c.getPageNumber()
    c.setFont("Helvetica", 9)
    c.setFillColor(colors.grey)
    c.drawRightString(PAGE_W - MARGIN_R, MARGIN_B - 6, f"Página {page}")
    c.setFillColor(colors.black)

# =============================
# GRÁFICOS (pizza + barras + heatmap)
# =============================
def draw_pie_with_values(c, counts, title, origin_x, origin_y):
    total = sum(counts.values()) or 1
    d = Drawing(380, 260)
    d.add(String(0, 240, title, fontName="Helvetica-Bold", fontSize=14, fillColor=colors.black))

    pie = Pie()
    pie.x = 30
    pie.y = 20
    pie.width  = 220
    pie.height = 220
    pie.data   = [counts[s] for s in SEV_ORDER]
    # rótulos com valor e %
    pie.labels = [f"{s} {counts[s]} ({(counts[s]/total*100):.0f}%)" for s in SEV_ORDER]
    pie.sideLabels = True
    pie.slices.strokeWidth = 0.3

    for i, s in enumerate(SEV_ORDER):
        pie.slices[i].fillColor = SEV_COLORS[s]

    d.add(pie)
    renderPDF.draw(d, c, origin_x, origin_y)

def draw_bars_with_values(c, sem_counts, tri_counts, title, origin_x, origin_y):
    d = Drawing(420, 260)
    d.add(String(0, 240, title, fontName="Helvetica-Bold", fontSize=14, fillColor=colors.black))

    bar = VerticalBarChart()
    bar.x = 40
    bar.y = 40
    bar.width  = 320
    bar.height = 160

    A = [sem_counts[s] for s in SEV_ORDER]
    B = [tri_counts[s] for s in SEV_ORDER]
    bar.data = [A, B]
    bar.categoryAxis.categoryNames = SEV_ORDER
    bar.groupSpacing = 8
    bar.barSpacing   = 2

    bar.bars[0].fillColor = ORANGE_DARK
    bar.bars[1].fillColor = ORANGE_PRIMARY
    bar.barLabelFormat = '%0.0f'
    bar.barLabels.nudge = 6
    bar.barLabels.fontName = "Helvetica"
    bar.barLabels.fontSize = 8

    bar.valueAxis.valueMin = 0
    bar.valueAxis.labelTextFormat = '%d'

    d.add(bar)

    leg = Legend()
    leg.x = 280
    leg.y = 220
    leg.fontName = "Helvetica"
    leg.fontSize = 9
    leg.alignment = 'right'
    leg.colorNamePairs = [
        (ORANGE_DARK,   "Semgrep"),
        (ORANGE_PRIMARY,"Trivy"),
    ]
    d.add(leg)

    renderPDF.draw(d, c, origin_x, origin_y)

def draw_heatmap(c, sem_counts, tri_counts, title, origin_x, origin_y):
    """Heatmap 2 x 5 (linhas: Semgrep, Trivy; colunas: severidades)."""
    grid_w = 360
    grid_h = 120
    cell_w = grid_w / len(SEV_ORDER)
    cell_h = grid_h / 2

    d = Drawing(grid_w, grid_h + 40)
    d.add(String(0, grid_h + 30, title, fontName="Helvetica-Bold", fontSize=14, fillColor=colors.black))

    max_val = max( [*sem_counts.values(), *tri_counts.values(), 1] )

    # linhas: 0=Semgrep, 1=Trivy
    for r, src in enumerate(["Semgrep","Trivy"]):
        for c_idx, sev in enumerate(SEV_ORDER):
            v = sem_counts[sev] if r == 0 else tri_counts[sev]
            intensity = v / max_val if max_val else 0
            # gradiente do claro p/ laranja primária
            base = colors.Color(1.0, 0.97, 0.93)  # bem claro
            mix  = ORANGE_PRIMARY
            fill = colors.Color(
                base.red   + (mix.red   - base.red)   * intensity,
                base.green + (mix.green - base.green) * intensity,
                base.blue  + (mix.blue  - base.blue)  * intensity
            )
            x = c_idx * cell_w
            y = (1 - r) * cell_h  # Semgrep em cima
            rect = Rect(x, y, cell_w - 4, cell_h - 4, strokeWidth=0.2, strokeColor=colors.lightgrey, fillColor=fill)
            d.add(rect)
            # valor ao centro
            d.add(String(x + cell_w/2 - 6, y + cell_h/2 - 6, str(v), fontName="Helvetica", fontSize=10, fillColor=colors.black))

    renderPDF.draw(d, c, origin_x, origin_y)

# =============================
# RISCO & CVSS
# =============================
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
    if not scores:
        return None
    return sum(scores)/len(scores)

# =============================
# TABELAS
# =============================
def draw_table_header(c, y):
    c.setFillColor(ORANGE_PRIMARY)
    c.rect(MARGIN_L, y-16, CONTENT_W, 18, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN_L + 6, y-3, "Sev")
    c.drawString(MARGIN_L + COL_W_SEV + 6, y-3, "Origem")
    c.drawString(MARGIN_L + COL_W_SEV + COL_W_ORIG + 6, y-3, "Detalhe")
    c.setFillColor(colors.black)
    return y - 22

def draw_table_rows(c, items, start_y):
    y = start_y
    c.setFont("Helvetica", 10)
    for idx, it in enumerate(items):
        sev = (it.get("severity") or "UNKNOWN").upper()
        origem = it.get("file", it.get("pkg", ""))
        # Detalhe: inclui CVSS se houver (para Trivy)
        if "id" in it:
            detalhe = f"{it.get('id','')} | {it.get('installed','')} -> {it.get('fixed','')}"
            if it.get("cvss") is not None:
                detalhe += f" | CVSS {it['cvss']:.1f}"
        else:
            detalhe = it.get("message","")

        # Quebras por coluna
        sev_lines = wrap_text(c, sev, COL_W_SEV - 12)
        org_lines = wrap_text(c, origem, COL_W_ORIG - 12)
        det_lines = wrap_text(c, detalhe, COL_W_DET - 12)

        row_lines = max(len(sev_lines), len(org_lines), len(det_lines))
        row_h = ROW_PAD_Y*2 + row_lines * LINE_H

        # quebra de página + cabeçalho novamente
        if y - row_h < MARGIN_B + 10:
            draw_footer(c)
            c.showPage()
            y = PAGE_H - MARGIN_T
            y = draw_table_header(c, y)

        # Zebra
        if idx % 2 == 0:
            c.setFillColor(ZEBRA_BG)
            c.rect(MARGIN_L, y - row_h, CONTENT_W, row_h, fill=1, stroke=0)
            c.setFillColor(colors.black)

        # Badge por severidade
        c.setFillColor(SEV_COLORS.get(sev, colors.black))
        c.roundRect(MARGIN_L + 6, y - ROW_PAD_Y - LINE_H, COL_W_SEV - 12, LINE_H+4, 3, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN_L + 10, y - ROW_PAD_Y - LINE_H + 2, sev)
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 10)

        # Origem
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in org_lines:
            c.drawString(MARGIN_L + COL_W_SEV + 6, tx_y, ln)
            tx_y -= LINE_H

        # Detalhe
        tx_y = y - ROW_PAD_Y - LINE_H + 2
        for ln in det_lines:
            c.drawString(MARGIN_L + COL_W_SEV + COL_W_ORIG + 6, tx_y, ln)
            tx_y -= LINE_H

        y -= row_h
    return y

# =============================
# SUMÁRIO (TOC)
# =============================
def build_toc_pdf(toc_items, outfile="toc.pdf"):
    """Gera um Sumário simples (1 página na prática)."""
    c = canvas.Canvas(outfile, pagesize=A4)
    y = PAGE_H - MARGIN_T
    c.setFont("Helvetica-Bold", 20)
    c.drawString(MARGIN_L, y, "Sumário")
    y -= 22
    c.setLineWidth(0.7)
    c.setStrokeColor(colors.HexColor("#e5e7eb"))
    c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
    y -= 16

    c.setFont("Helvetica", 12)
    for title, page in toc_items:
        line = f"{title}"
        c.drawString(MARGIN_L, y, line)
        c.drawRightString(MARGIN_L + CONTENT_W, y, str(page))
        y -= 16
        if y < MARGIN_B + 20:
            c.showPage()
            y = PAGE_H - MARGIN_T
            c.setFont("Helvetica-Bold", 20)
            c.drawString(MARGIN_L, y, "Sumário (cont.)")
            y -= 22
            c.setLineWidth(0.7)
            c.setStrokeColor(colors.HexColor("#e5e7eb"))
            c.line(MARGIN_L, y, MARGIN_L + CONTENT_W, y)
            y -= 16
            c.setFont("Helvetica", 12)

    c.save()

def merge_cover_toc_content(content_path="content.pdf", toc_path="toc.pdf", out_path="security-report.pdf"):
    """Final: capa (p1 do content) + toc + restante do content."""
    if PdfReader is None or PdfWriter is None:
        # fallback: se não tiver PyPDF2, mantém content.pdf como final
        try:
            os.replace(content_path, out_path)
        except Exception:
            pass
        return

    reader = PdfReader(content_path)
    writer = PdfWriter()
    # capa
    writer.add_page(reader.pages[0])
    # toc
    toc_reader = PdfReader(toc_path)
    for p in toc_reader.pages:
        writer.add_page(p)
    # restante do conteúdo
    for i in range(1, len(reader.pages)):
        writer.add_page(reader.pages[i])
    with open(out_path, "wb") as f:
        writer.write(f)

# =============================
# PRINCIPAL
# =============================
def main():
    # 1) Carregar dados
    semgrep = load_semgrep()
    trivy   = load_trivy()
    semgrep_counts = count_by_severity(semgrep)
    trivy_counts   = count_by_severity(trivy)

    # 2) Criar CONTENT (capa + resumo + gráficos + tabelas) e marcar páginas
    section_pages = {}  # nome -> página no content.pdf
    c = canvas.Canvas("content.pdf", pagesize=A4)

    # Capa
    draw_cover(c)
    # Nota: após draw_cover(), estamos na página 2.

    # --- Resumo Executivo ---
    section_pages["Resumo Executivo"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Resumo Executivo", y)

    # Marcadores de Risco
    risks = risk_markers(semgrep_counts, trivy_counts)
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(SEV_COLORS["CRITICAL"])
    c.drawString(MARGIN_L, y, f"Risco Imediato (CRITICAL): {risks['imediato']}")
    y -= 16
    c.setFillColor(SEV_COLORS["HIGH"])
    c.drawString(MARGIN_L, y, f"Risco Alto (HIGH): {risks['alto']}")
    y -= 16
    c.setFillColor(SEV_COLORS["MEDIUM"])
    c.drawString(MARGIN_L, y, f"Risco Médio (MEDIUM): {risks['medio']}")
    y -= 16
    c.setFillColor(SEV_COLORS["LOW"])
    c.drawString(MARGIN_L, y, f"Monitoramento (LOW/UNKNOWN): {risks['monitor']}")
    y -= 24

    # CVSS médio (Trivy)
    c.setFillColor(colors.black)
    avg = avg_cvss(trivy)
    if avg is not None:
        c.drawString(MARGIN_L, y, f"CVSS médio (prioridade 4.0; fallback 3.x): {avg:.1f}")
    else:
        c.drawString(MARGIN_L, y, "CVSS médio: N/A")
    y -= 24

    # Heatmap
    draw_heatmap(c, semgrep_counts, trivy_counts, "Heatmap de Severidade (Semgrep x Trivy)", MARGIN_L, y - 160)
    draw_footer(c)
    c.showPage()

    # --- Gráficos ---
    section_pages["Visão Geral – Gráficos"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Visão Geral – Gráficos", y)
    # Pizza (Semgrep) + Barras (Semgrep x Trivy)
    draw_pie_with_values(c, semgrep_counts, "Distribuição por Severidade – Semgrep", MARGIN_L, y - 260)
    draw_bars_with_values(c, semgrep_counts, trivy_counts, "Semgrep x Trivy por Severidade", MARGIN_L, y - 540)
    draw_footer(c)
    c.showPage()

    # --- Tabela Semgrep ---
    section_pages["Tabela de Achados – Semgrep"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Tabela de Achados – Semgrep", y)
    y = draw_table_header(c, y)
    y = draw_table_rows(c, semgrep[:MAX_ROWS_SEMGREP], y)
    draw_footer(c)
    c.showPage()

    # --- Tabela Trivy ---
    section_pages["Tabela de Vulnerabilidades – Trivy"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Tabela de Vulnerabilidades – Trivy", y)
    y = draw_table_header(c, y)
    y = draw_table_rows(c, trivy[:MAX_ROWS_TRIVY], y)
    draw_footer(c)
    c.showPage()

    # encerrar content
    c.save()

    # 3) Gerar TOC (somamos +1 página ao número das seções pois inseriremos o TOC após capa)
    toc_items = []
    for name, p in section_pages.items():
        final_page = p + 1 if p >= 2 else p  # capa=1; demais deslocam +1
        toc_items.append((name, final_page))

    build_toc_pdf(toc_items, "toc.pdf")

    # 4) Mesclar: capa (content p1) + TOC + restante conteúdo
    merge_cover_toc_content("content.pdf", "toc.pdf", "security-report.pdf")

    # 5) Limpeza opcional (mantenha se quiser inspecionar)
    try:
        os.remove("content.pdf")
        os.remove("toc.pdf")
    except Exception:
        pass

if __name__ == "__main__":
    main()
