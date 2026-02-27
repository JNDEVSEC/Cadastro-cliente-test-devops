from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import mm
from datetime import datetime
import json
import os

ORG_NAME = "Sua Empresa"
TITLE = "Relatório de Segurança - Semgrep & Trivy"
DATE_STR = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")

def wrap_text(c, text, max_width):
    words = text.split()
    lines, line = [], ""
    for w in words:
        test = f"{line} {w}".strip()
        if c.stringWidth(test, "Helvetica", 11) <= max_width:
            line = test
        else:
            if line:
                lines.append(line)
            line = w
    if line:
        lines.append(line)
    return lines

def cover_page(c):
    c.setFillColor(colors.HexColor("#0f172a"))
    c.rect(0, 0, A4[0], A4[1], fill=1)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 26)
    c.drawString(40, 750, TITLE)
    c.setFont("Helvetica", 14)
    c.drawString(40, 720, f"Organização: {ORG_NAME}")
    c.drawString(40, 700, f"Data: {DATE_STR}")
    c.showPage()

def section(c, title, items):
    y = 800
    c.setFont("Helvetica-Bold", 20)
    c.drawString(40, y, title)
    y -= 30
    c.setFont("Helvetica", 11)
    for text in items:
        # page break
        if y < 40:
            c.showPage()
            y = 800
            c.setFont("Helvetica", 11)

        lines = wrap_text(c, text, 500)
        for ln in lines:
            c.drawString(40, y, ln)
            y -= 16

    c.showPage()

def main():
    semgrep_items = []
    trivy_items = []

    if os.path.exists("semgrep.report.json"):
        with open("semgrep.report.json") as f:
            data = json.load(f)
            for r in data.get("results", []):
                semgrep_items.append(
                    f"[{r['severity']}] {r['file']}:{r['line']} — {r['message']}"
                )

    if os.path.exists("trivy-results.json"):
        data = json.load(open("trivy-results.json"))
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities", []):
                trivy_items.append(
                    f"[{v['Severity']}] {v['VulnerabilityID']} — {v['PkgName']} "
                    f"({v.get('InstalledVersion','?')} -> {v.get('FixedVersion','-')})"
                )

    c = canvas.Canvas("security-report.pdf", pagesize=A4)
    cover_page(c)
    section(c, "Seção A — Semgrep", semgrep_items)
    section(c, "Seção B — Trivy (Vulnerabilities)", trivy_items)
    c.save()

if __name__ == "__main__":
    main()
``
