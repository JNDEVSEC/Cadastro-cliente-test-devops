from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.lib.units import mm
from datetime import datetime
import json
import os

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

SEV_COLORS = {
    "CRITICAL": colors.red,
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#f97316"),
    "LOW": colors.HexColor("#fed7aa"),
    "UNKNOWN": colors.grey,
}

# =============================
# FUNÇÕES DE APOIO
# =============================
def wrap_text(c, text, width):
    words = text.split()
    line = ""
    lines = []
    for w in words:
        new = (line + " " + w).strip()
        if c.stringWidth(new, "Helvetica", 10) <= width:
            line = new
        else:
            lines.append(line)
            line = w
    if line:
        lines.append(line)
    return lines

def load_semgrep():
    if not os.path.exists("semgrep.report.json"):
        return []
    data = json.load(open("semgrep.report.json"))
    out = []
    for r in data.get("results", []):
        out.append({
            "severity": r.get("severity", "").upper(),
            "file": r.get("file", ""),
            "line": r.get("line", ""),
            "message": r.get("message", "")
        })
    return out

def load_trivy():
    if not os.path.exists("trivy-results.json"):
        return []
    data = json.load(open("trivy-results.json"))
    out = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            out.append({
                "severity": v.get("Severity", "UNKNOWN").upper(),
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion") or "-",
            })
    return out

def count_by_severity(items):
    counts = {s: 0 for s in SEV_ORDER}
    for it in items:
        sev = it.get("severity", "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1
    return counts

# =============================
# CAPA
# =============================
def draw_cover(c):
    c.setFillColor(colors.HexColor("#ea580c"))
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 32)
    c.drawString(50, PAGE_H - 150, TITLE)

    c.setFont("Helvetica", 18)
    c.drawString(50, PAGE_H - 190, f"Empresa: {ORG_NAME}")

    c.setFont("Helvetica", 14)
    c.drawString(50, PAGE_H - 220, f"Gerado em: {DATE_STR}")

    c.showPage()

# =============================
# GRÁFICOS
# =============================
def draw_pie(c, counts, title):
    d = Drawing(300, 200)
    pie = Pie()
    pie.x = 40
    pie.y = 15
    pie.width = 200
    pie.height = 200
    pie.data = [counts[s] for s in SEV_ORDER]
    pie.labels = SEV_ORDER

    for i, s in enumerate(SEV_ORDER):
        pie.slices[i].fillColor = SEV_COLORS[s]

    d.add(pie)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, PAGE_H - 50, title)

    renderPDF.draw(d, c, 50, PAGE_H - 320)

def draw_bars(c, semgrep_counts, trivy_counts, title):
    d = Drawing(400, 250)
    bar = VerticalBarChart()
    bar.x = 50
    bar.y = 40
    bar.height = 150
    bar.width = 300

    bar.data = [
        [semgrep_counts[s] for s in SEV_ORDER],
        [trivy_counts[s] for s in SEV_ORDER]
    ]

    bar.categoryAxis.categoryNames = SEV_ORDER
    bar.barWidth = 16

    bar.bars[0].fillColor = colors.HexColor("#ea580c")
    bar.bars[1].fillColor = colors.HexColor("#f97316")

    d.add(bar)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, PAGE_H - 350, title)

    renderPDF.draw(d, c, 50, PAGE_H - 650)

# =============================
# TABELA
# =============================
def draw_table(c, items, title):
    c.setFont("Helvetica-Bold", 20)
    c.drawString(40, PAGE_H - 60, title)

    y = PAGE_H - 90
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Sev")
    c.drawString(90, y, "Origem")
    c.drawString(350, y, "Detalhe")

    y -= 20
    c.setFont("Helvetica", 10)

    for i, item in enumerate(items):
        if y < 50:
            c.showPage()
            y = PAGE_H - 80
            c.setFont("Helvetica", 10)

        # Faixa zebradas
        if i % 2 == 0:
            c.setFillColor(colors.HexColor("#fed7aa"))
            c.rect(30, y - 3, PAGE_W - 60, 15, fill=1, stroke=0)
            c.setFillColor(colors.black)

        severity = item.get("severity", "UNKNOWN")
        c.drawString(40, y, severity)

        key = item.get("file", item.get("pkg", ""))
        c.drawString(90, y, key[:30])

        msg = item.get("message", f"{item.get('id','')} {item.get('installed','')} -> {item.get('fixed','')}")
        lines = wrap_text(c, msg, 250)
        c.drawString(350, y, lines[0][:60])

        y -= 16

    c.showPage()

# =============================
# PRINCIPAL
# =============================
def main():
    semgrep = load_semgrep()
    trivy = load_trivy()

    semgrep_counts = count_by_severity(semgrep)
    trivy_counts = count_by_severity(trivy)

    c = canvas.Canvas("security-report.pdf", pagesize=A4)

    # Capa
    draw_cover(c)

    # Página 2 — gráficos
    draw_pie(c, semgrep_counts, "Distribuição de Severidade — Semgrep")
    draw_bars(c, semgrep_counts, trivy_counts, "Severidade Semgrep x Trivy")
    c.showPage()

    # Página 3 — Tabelas executivas
    draw_table(c, semgrep[:50], "Tabela Semgrep (Top 50)")
    draw_table(c, trivy[:50], "Tabela Trivy (Top 50)")

    c.save()

if __name__ == "__main__":
    main()
