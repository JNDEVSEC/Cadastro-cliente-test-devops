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
