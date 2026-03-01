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
    "CRITICAL": colors.Color(0.85, 0.10, 0.10, alpha=1),  # vermelho rubro forte (exato)
    "HIGH":     colors.HexColor("#ea580c"),               # laranja escuro
    "MEDIUM":   colors.HexColor("#f97316"),               # laranja médio
    "LOW":      colors.HexColor("#fed7aa"),               # laranja claro
    "UNKNOWN":  colors.Color(0.60, 0.60, 0.60),           # cinza
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
