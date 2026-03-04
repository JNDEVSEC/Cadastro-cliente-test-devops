#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from datetime import datetime, timezone
from math import isfinite

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from reportlab.graphics.shapes import Drawing, String, Rect
from reportlab.graphics import renderPDF
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend

# ========== CONFIG EXECUTIVA & TEMA ==========
ORG_NAME = os.getenv("ORG_NAME", "Sua Empresa")
TITLE    = os.getenv("REPORT_TITLE", "Relatório Executivo de Segurança")
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

SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"]

# Paleta
SEV_COLORS = {
    "CRITICAL": colors.Color(0.85, 0.10, 0.10, alpha=1),
    "HIGH":     colors.HexColor("#ea580c"),
    "MEDIUM":   colors.HexColor("#f97316"),
    "LOW":      colors.HexColor("#fed7aa"),
    "INFO":     colors.Color(0.55, 0.60, 0.70),
    "UNKNOWN":  colors.Color(0.60, 0.60, 0.60),
}
ORANGE_PRIMARY  = colors.HexColor("#f97316")
ORANGE_DARK     = colors.HexColor("#ea580c")
ORANGE_LIGHT_BG = colors.HexColor("#fff7ed")

# =========================================================
# UTILITÁRIAS
# =========================================================
def wrap_lines(c, text, width, font="Helvetica", size=FONT_S):
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
            test = (current + " " + word).strip()
            if c.stringWidth(test, font, size) <= width:
                current = test
            else:
                flush_current()
                current = word
        else:
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
                current = chunk
    flush_current()
    return lines

def draw_bullet_paragraph(c, x, y, text, max_width, bullet="• ", font="Helvetica", size=FONT_S):
    c.setFont(font, size)
    bullet_w = c.stringWidth(bullet, font, size)
    lines = wrap_lines(c, text, max_width - bullet_w, font=font, size=size)
    c.drawString(x, y, bullet + (lines[0] if lines else ""))
    y -= LINE_H
    cont_x = x + bullet_w
    for ln in lines[1:]:
        c.drawString(cont_x, y, ln)
        y -= LINE_H
    return y

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

def safe_load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# -------- SEMGREP (json nativo) --------

def load_semgrep_rich():
    if not os.path.exists("semgrep.json"):
        return []
    data = safe_load_json("semgrep.json") or {}
    out = []
    for r in (data.get("results") or []):
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

# -------- TRIVY: suporte a JSON (opcional legacy) e SARIF --------

SARIF_SEV_FROM_LEVEL = {
    "error": "HIGH",    # mapeamento conservador
    "warning": "MEDIUM",
    "note": "LOW",
}

TRIVY_SARIF_FILES_VULN = [
    "trivy-image.sarif",
    "trivy-fs-vuln.sarif",
]
TRIVY_SARIF_FILES_SECRETS = [
    "trivy-fs-secrets.sarif",
]
TRIVY_SARIF_FILES_CONFIG = [
    "trivy-config.sarif",
    "trivy-config-dockerfile.sarif",
]


def _norm_severity(value, fallback="UNKNOWN"):
    if not value:
        return fallback
    v = str(value).upper()
    if v in SEV_ORDER:
        return v
    # tentar float (ex: security-severity "7.5")
    try:
        f = float(str(value))
        if f >= 9.0: return "CRITICAL"
        if f >= 7.0: return "HIGH"
        if f >= 4.0: return "MEDIUM"
        if f > 0:    return "LOW"
        return "INFO"
    except Exception:
        pass
    # tentar level -> sev
    low = str(value).lower()
    return SARIF_SEV_FROM_LEVEL.get(low, fallback)


def _try_parse_pkg_from_message(msg: str):
    # Trivy geralmente inclui linhas como: "Package: X\nInstalled: 1.2\nFixed Version: 1.3" no message.text do SARIF
    pkg = installed = fixed = None
    if not msg:
        return pkg, installed, fixed
    # padrões tolerantes
    m = re.search(r"(?i)package\s*:\s*([\w\-\.@/]+)", msg)
    if m: pkg = m.group(1).strip()
    m = re.search(r"(?i)installed\s*:\s*([\w\-\.@:/]+)", msg)
    if m: installed = m.group(1).strip()
    m = re.search(r"(?i)(fixed|fix(?:ed)?\s*version)\s*:\s*([\w\-\.@:/]+)", msg)
    if m: fixed = m.group(2).strip()
    return pkg, installed, fixed


def load_trivy_vulns_from_sarif(paths):
    out = []
    for p in paths:
        if not os.path.exists(p):
            continue
        data = safe_load_json(p) or {}
        for run in (data.get("runs") or []):
            rules_map = {}
            try:
                for rule in ((run.get("tool", {}) or {}).get("driver", {})
                              .get("rules", []) or []):
                    rid = rule.get("id")
                    rules_map[rid] = rule
            except Exception:
                pass
            for r in (run.get("results") or []):
                rid = r.get("ruleId") or (r.get("rule", {}) or {}).get("id")
                level = (r.get("level") or "").lower()
                props = r.get("properties", {}) or {}
                sev = _norm_severity(props.get("severity") or props.get("problem.severity") or level or "UNKNOWN")
                msg = ((r.get("message") or {}).get("text") or "").strip()
                locations = r.get("locations") or []
                file = line = None
                if locations:
                    pl = ((locations[0] or {}).get("physicalLocation") or {})
                    file = ((pl.get("artifactLocation") or {}).get("uri") or
                            (pl.get("artifactLocation") or {}).get("uriBaseId"))
                    region = pl.get("region") or {}
                    line = region.get("startLine")
                # Complementa com rule description/title quando possível
                title = None
                url = None
                cvss = None
                if rid and rid in rules_map:
                    rule = rules_map[rid]
                    title = ((rule.get("shortDescription") or {}).get("text") or
                             (rule.get("fullDescription") or {}).get("text"))
                    rprops = rule.get("properties", {}) or {}
                    # Alguns SARIF do Trivy incluem "security-severity" ou "precision" etc.
                    for k in ("security-severity", "cvssScore", "cvss", "cvss_v3", "cvssV3"):
                        try:
                            v = rprops.get(k)
                            if v is not None:
                                f = float(v)
                                if cvss is None or f > cvss:
                                    cvss = f
                        except Exception:
                            pass
                    url = (rprops.get("uri") or rprops.get("url") or None)
                # Extrai pkg/versions do texto
                pkg, installed, fixed = _try_parse_pkg_from_message(msg)
                # Normaliza
                out.append({
                    "id": rid or "",
                    "title": title or "",
                    "description": msg,
                    "severity": sev,
                    "pkg": pkg or "",
                    "installed": installed or "",
                    "fixed": fixed or "-",
                    "cvss": cvss,
                    "url": url,
                    "file": file or "",
                    "line": line or 1,
                    "source": os.path.basename(p),
                })
    return out


def load_trivy_secrets_from_sarif(paths):
    out = []
    for p in paths:
        if not os.path.exists(p):
            continue
        data = safe_load_json(p) or {}
        for run in (data.get("runs") or []):
            rules_map = {}
            try:
                for rule in ((run.get("tool", {}) or {}).get("driver", {})
                              .get("rules", []) or []):
                    rid = rule.get("id")
                    rules_map[rid] = rule
            except Exception:
                pass
            for r in (run.get("results") or []):
                rid = r.get("ruleId") or (r.get("rule", {}) or {}).get("id")
                level = (r.get("level") or "").lower()
                props = r.get("properties", {}) or {}
                sev = _norm_severity(props.get("severity") or props.get("problem.severity") or level or "UNKNOWN")
                msg = ((r.get("message") or {}).get("text") or "").strip()
                locations = r.get("locations") or []
                file = line = None
                if locations:
                    pl = ((locations[0] or {}).get("physicalLocation") or {})
                    file = ((pl.get("artifactLocation") or {}).get("uri") or
                            (pl.get("artifactLocation") or {}).get("uriBaseId"))
                    region = pl.get("region") or {}
                    line = region.get("startLine")
                title = None
                if rid and rid in rules_map:
                    rule = rules_map[rid]
                    title = ((rule.get("shortDescription") or {}).get("text") or
                             (rule.get("fullDescription") or {}).get("text"))
                out.append({
                    "rule_id": rid or "",
                    "title": title or "Possible secret exposed",
                    "severity": sev,
                    "file": file or "",
                    "line": line or 1,
                    "message": msg,
                    "source": os.path.basename(p),
                })
    return out


def load_trivy_config_from_sarif(paths):
    out = []
    for p in paths:
        if not os.path.exists(p):
            continue
        data = safe_load_json(p) or {}
        for run in (data.get("runs") or []):
            rules_map = {}
            try:
                for rule in ((run.get("tool", {}) or {}).get("driver", {})
                              .get("rules", []) or []):
                    rid = rule.get("id")
                    rules_map[rid] = rule
            except Exception:
                pass
            for r in (run.get("results") or []):
                rid = r.get("ruleId") or (r.get("rule", {}) or {}).get("id")
                level = (r.get("level") or "").lower()
                props = r.get("properties", {}) or {}
                sev = _norm_severity(props.get("severity") or props.get("problem.severity") or level or "UNKNOWN")
                msg = ((r.get("message") or {}).get("text") or "").strip()
                locations = r.get("locations") or []
                file = line = None
                if locations:
                    pl = ((locations[0] or {}).get("physicalLocation") or {})
                    file = ((pl.get("artifactLocation") or {}).get("uri") or
                            (pl.get("artifactLocation") or {}).get("uriBaseId"))
                    region = pl.get("region") or {}
                    line = region.get("startLine")
                title = None
                if rid and rid in rules_map:
                    rule = rules_map[rid]
                    title = ((rule.get("shortDescription") or {}).get("text") or
                             (rule.get("fullDescription") or {}).get("text"))
                out.append({
                    "rule_id": rid or "",
                    "title": title or "Misconfiguration",
                    "severity": sev,
                    "file": file or "",
                    "line": line or 1,
                    "message": msg,
                    "source": os.path.basename(p),
                })
    return out

# -------- Custom Review (JSON) --------

def load_custom_review():
    path = "custom-review.json"
    data = safe_load_json(path)
    if not data:
        return []
    results = data.get("results", []) or []
    out = []
    for r in results:
        sev = (r.get("severity") or "UNKNOWN").upper()
        if sev not in SEV_ORDER:
            sev = "INFO"
        out.append({
            "rule_id": r.get("rule_id") or r.get("id") or "",
            "title":   r.get("title") or r.get("name") or "",
            "severity": sev,
            "file":    r.get("file") or "",
            "line":    r.get("line") or 1,
            "message": r.get("message") or "",
            "snippet": r.get("snippet") or "",
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

def draw_bars_with_values_single(c, counts_dict, title, origin_x, origin_y, width=400, height=240):
    c.setFont("Helvetica-Bold", FONT_L); c.setFillColor(colors.black)
    c.drawString(origin_x, origin_y + height - 10, title)

    d = Drawing(width, height - 20)
    bar = VerticalBarChart()
    bar.x, bar.y = 36, 32
    bar.width, bar.height = width - 80, height - 80
    ordered_sev = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    data = [int(counts_dict.get(s, 0) or 0) for s in ordered_sev]
    bar.data = [data]
    bar.categoryAxis.categoryNames = ordered_sev
    bar.groupSpacing = 6
    bar.barSpacing = 1.5
    bar.barWidth = 14
    bar.valueAxis.valueMin = 0
    bar.valueAxis.labelTextFormat = '%d'
    # colorir barras
    try:
        # reportlab>=3.6.13 tem .bars, versões antigas não; fallback colorir através de style ranges não trivial, então ignoramos se falhar
        for i, sev in enumerate(ordered_sev):
            bar.bars[i].fillColor = SEV_COLORS.get(sev, colors.lightgrey)
    except Exception:
        pass
    bar.barLabelFormat = '%0.0f'
    bar.barLabels.nudge = 5
    bar.barLabels.fontName = "Helvetica"
    bar.barLabels.fontSize = FONT_S
    d.add(bar)
    renderPDF.draw(d, c, origin_x, origin_y)


def draw_grouped_bars_by_severity(c, left_counts, right_counts, title, x, y, width=400, height=240, left_label="Semgrep", right_label="Trivy (CVEs)"):
    top_title_h = 22
    bottom_axis_h = 22
    left_pad = 32
    right_pad = 16
    chart_w = max(100, width - left_pad - right_pad)
    chart_h = max(80, height - top_title_h - bottom_axis_h)

    d = Drawing(width, height)
    d.add(String(width / 2.0, height - 6, title,
                 fontName="Helvetica-Bold", fontSize=14, textAnchor="middle"))

    severities = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    ymax = max([left_counts.get(s, 0) for s in severities] +
               [right_counts.get(s, 0) for s in severities] + [0])
    if ymax < 5:
        ymax = 5

    group_pad = 14
    bar_w = 10
    gap_in_group = 6
    group_w = (2 * bar_w) + gap_in_group
    total_groups_w = len(severities) * group_w + (len(severities) - 1) * group_pad

    scale_x = min(1.0, chart_w / float(total_groups_w))
    scale_y = chart_h / float(max(1, ymax))

    ox = left_pad
    oy = bottom_axis_h

    d.add(Rect(ox - 1, oy - 1, chart_w + 2, 1.2, fillColor=colors.black, strokeWidth=0))

    cursor_x = ox
    labels_y = oy - 12

    for s in severities:
        sev_color = SEV_COLORS.get(s, colors.lightgrey)
        vl = int(left_counts.get(s, 0) or 0)
        vr = int(right_counts.get(s, 0) or 0)

        h_l = vl * scale_y
        h_r = vr * scale_y

        bx_l = cursor_x
        bx_r = cursor_x + bar_w + gap_in_group

        d.add(Rect(bx_l, oy, bar_w, h_l,
                   fillColor=sev_color, strokeColor=colors.black, strokeWidth=0.2))
        if vl > 0:
            d.add(String(bx_l + bar_w/2.0, oy + h_l + 6, str(vl),
                         fontName="Helvetica", fontSize=9, textAnchor="middle"))

        d.add(Rect(bx_r, oy, bar_w, h_r,
                   fillColor=sev_color, strokeColor=colors.black, strokeWidth=0.2))
        if vr > 0:
            d.add(String(bx_r + bar_w/2.0, oy + h_r + 6, str(vr),
                         fontName="Helvetica", fontSize=9, textAnchor="middle"))

        d.add(String(cursor_x + group_w/2.0, labels_y, s,
                     fontName="Helvetica", fontSize=9, textAnchor="middle"))

        cursor_x += (group_w + group_pad)

    if scale_x < 1.0:
        d.scale(scale_x, 1.0)
        d.translate(ox * (1 - scale_x) / scale_x, 0)

    leg = Legend()
    leg.fontName = "Helvetica"
    leg.fontSize = 10
    leg.alignment = 'right'
    leg.x = width - 160
    leg.y = height - 26
    leg.colorNamePairs = [
        (ORANGE_DARK, left_label),
        (ORANGE_PRIMARY, right_label),
    ]
    d.add(leg)

    renderPDF.draw(d, c, x, y)

# =========================================================
# RISCO & CVSS
# =========================================================

def avg_cvss(trivy):
    scores = [v.get("cvss") for v in trivy if isinstance(v.get("cvss"), (int,float))]
    scores = [s for s in scores if s is not None and isfinite(s)]
    return (sum(scores)/len(scores)) if scores else None

# =========================================================
# TÓPICOS (Semgrep, Trivy, Secrets, Config, Custom Review)
# =========================================================

def draw_topic(c, y, heading, items, color=None):
    heading_lines = wrap_lines(c, heading, CONTENT_W - 20, font="Helvetica-Bold", size=FONT_M)
    heading_height = len(heading_lines) * LINE_H + 8

    bullets_est_h = max(LINE_H * 2 * len(items), LINE_H * len(items)) + 8

    need_h = heading_height + bullets_est_h + 12
    if y - need_h < MARGIN_B + 10:
        draw_footer(c)
        c.showPage()
        y = PAGE_H - MARGIN_T

    x = MARGIN_L
    if color:
        c.setFillColor(color)
        c.roundRect(x, y-14, 10, 10, 2.5, fill=1, stroke=0)
        x += 16

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", FONT_M)
    for hl in heading_lines:
        c.drawString(x, y, hl)
        y -= LINE_H
    y -= 4

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
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Vulnerabilidades – SAST (Semgrep)", y)
    for r in semgrep:
        sev = (r.get("severity") or "UNKNOWN").upper()
        heading = f"[{sev}] {r.get('rule_id','')}".strip()
        arquivo = f"Arquivo: {r.get('file','')}:{r.get('line','')}".strip(":")
        risco   = f"Risco: {r.get('message','')}" if r.get("message") else "Risco: (não informado pela regra)"
        fix     = r.get("fix")
        if fix:
            sugestao = f"Sugestão: {fix}"
        else:
            sugestao = "Sugestão: aplicar mitigação recomendada pela regra."
        refs = r.get("references") or []
        ref_line = f"Referências: {', '.join(refs[:2])}" if refs else None

        lines = [arquivo, risco, sugestao]
        if ref_line: lines.append(ref_line)
        y = draw_topic(c, y, heading, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()


def draw_trivy_topics(c, vulns):
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Vulnerabilidades – SCA (Trivy)", y)
    for v in vulns:
        sev   = (v.get("severity") or "UNKNOWN").upper()
        vid   = v.get("id","")
        title = v.get("title") or ""
        head  = f"[{sev}] {vid}" + (f" — {title}" if title else "")
        pkg   = v.get("pkg","")
        inst  = v.get("installed","")
        fix   = v.get("fixed","-")

        l_pkg  = f"Pacote: {pkg} ({inst} -> {fix})" if (pkg or inst or fix) else None
        l_cvss = f"CVSS: {v['cvss']:.1f}" if isinstance(v.get("cvss"), (int,float)) else None
        desc   = (v.get("description") or "").strip()
        l_risk = "Risco: " + (desc if desc else "(sem descrição do fornecedor)")
        l_fix  = f"Sugestão: atualizar para {fix}" if fix and fix != "-" else "Sugerido: verificar boletins/patch."
        url    = v.get("url")
        l_ref  = f"Referência: {url}" if url else None
        fileln = None
        if v.get("file"):
            fileln = f"Arquivo: {v.get('file')}:{v.get('line',1)}"
        src    = v.get("source")
        source = f"Fonte: {src}" if src else None

        lines = [ln for ln in [l_pkg, l_cvss, l_risk, l_fix, l_ref, fileln, source] if ln]
        y = draw_topic(c, y, head, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()


def draw_secrets_topics(c, secrets):
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Exposição de Segredos – (Trivy Secrets)", y)
    for f in secrets:
        sev   = (f.get("severity") or "UNKNOWN").upper()
        rid   = f.get("rule_id","")
        title = f.get("title") or "Secret detectado"
        head  = f"[{sev}] {rid}" + (f" — {title}" if title else "")
        fileline = f"Arquivo: {f.get('file','')}:{f.get('line',1)}".strip(":")
        msg  = f.get("message") or "(sem detalhes)"
        src  = f.get("source")
        src_line = f"Fonte: {src}" if src else None
        lines = [fileline, f"Mensagem: {msg}"]
        if src_line: lines.append(src_line)
        y = draw_topic(c, y, head, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()


def draw_config_topics(c, cfg):
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Misconfigurações – IaC/Config (Trivy)", y)
    for f in cfg:
        sev   = (f.get("severity") or "UNKNOWN").upper()
        rid   = f.get("rule_id","")
        title = f.get("title") or "Misconfiguration"
        head  = f"[{sev}] {rid}" + (f" — {title}" if title else "")
        fileline = f"Arquivo: {f.get('file','')}:{f.get('line',1)}".strip(":")
        msg  = f.get("message") or "(sem detalhes)"
        src  = f.get("source")
        src_line = f"Fonte: {src}" if src else None
        lines = [fileline, f"Mensagem: {msg}"]
        if src_line: lines.append(src_line)
        y = draw_topic(c, y, head, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()


def draw_custom_topics(c, findings):
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Achados – Custom Security Review", y)
    for f in findings:
        sev   = (f.get("severity") or "UNKNOWN").upper()
        rid   = f.get("rule_id","")
        title = f.get("title") or ""
        head  = f"[{sev}] {rid}" + (f" — {title}" if title else "")
        fileline = f"Arquivo: {f.get('file','')}:{f.get('line',1)}".strip(":")
        msg  = f.get("message") or None
        snip = f.get("snippet") or None
        lines = [ln for ln in [fileline, f"Mensagem: {msg}" if msg else None, f"Snippet: {snip[:180]}" if snip else None] if ln]
        y = draw_topic(c, y, head, lines, color=SEV_COLORS.get(sev, colors.grey))
    draw_footer(c); c.showPage()

# =========================================================
# SUMÁRIO (TOC) / MERGE PDF
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
    try:
        from PyPDF2 import PdfReader, PdfWriter
    except Exception:
        try:
            os.replace(content_path, out_path)
        except Exception:
            pass
        return
    reader = PdfReader(content_path); writer = PdfWriter()
    # capa
    writer.add_page(reader.pages[0])
    # sumário
    toc_reader = PdfReader(toc_path)
    for p in toc_reader.pages: writer.add_page(p)
    # demais
    for i in range(1, len(reader.pages)): writer.add_page(reader.pages[i])
    with open(out_path, "wb") as f: writer.write(f)

# =========================================================
# PRINCIPAL
# =========================================================

def main():
    # Carrega dados primários
    semgrep = load_semgrep_rich()

    # Trivy CVEs: tenta JSON legado (trivy-results.json); se não existir, usa SARIFs (image + fs-vuln)
    trivy_vulns = []
    if os.path.exists("trivy-results.json"):
        # Suporte a legado, reaproveitando estrutura original do script
        tri = safe_load_json("trivy-results.json") or {}
        for res in tri.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                sev = (v.get("Severity") or "UNKNOWN").upper()
                refs  = v.get("References") or []
                url   = v.get("PrimaryURL") or (refs[0] if refs else None)
                # Extrai melhor cvss possível
                cvss = None
                cvss_dict = v.get("CVSS") or {}
                try:
                    for _, dv in cvss_dict.items():
                        if isinstance(dv, dict):
                            for k in ("V4Score","V31Score","V30Score","Score","BaseScore"):
                                if k in dv:
                                    f = float(dv[k])
                                    if cvss is None or f > cvss:
                                        cvss = f
                except Exception:
                    cvss = None
                trivy_vulns.append({
                    "id": v.get("VulnerabilityID",""),
                    "title": v.get("Title") or "",
                    "description": v.get("Description") or "",
                    "severity": sev,
                    "pkg": v.get("PkgName",""),
                    "installed": v.get("InstalledVersion",""),
                    "fixed": v.get("FixedVersion") or "-",
                    "cvss": cvss,
                    "url": url,
                    "file": "",
                    "line": 1,
                    "source": "trivy-results.json",
                })
    else:
        trivy_vulns = load_trivy_vulns_from_sarif(TRIVY_SARIF_FILES_VULN)

    trivy_secrets = load_trivy_secrets_from_sarif(TRIVY_SARIF_FILES_SECRETS)
    trivy_config  = load_trivy_config_from_sarif(TRIVY_SARIF_FILES_CONFIG)

    custom  = load_custom_review()

    semgrep_counts = count_by_severity(semgrep, key="severity")
    trivy_counts   = count_by_severity(trivy_vulns,   key="severity")
    secrets_counts = count_by_severity(trivy_secrets, key="severity")
    config_counts  = count_by_severity(trivy_config,  key="severity")
    custom_counts  = count_by_severity(custom,        key="severity")

    # CONTENT (capa + seções)
    section_pages = {}
    c = canvas.Canvas("content.pdf", pagesize=A4)

    # Capa
    draw_cover(c)

    # Resumo Executivo
    section_pages["Resumo Executivo"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Resumo Executivo", y)

    c.setFont("Helvetica-Bold", FONT_M)
    risks = {
        "Risco Imediato (CRITICAL)": semgrep_counts["CRITICAL"] + trivy_counts["CRITICAL"] + secrets_counts["CRITICAL"] + config_counts["CRITICAL"] + custom_counts["CRITICAL"],
        "Risco Alto (HIGH)":         semgrep_counts["HIGH"]     + trivy_counts["HIGH"]     + secrets_counts["HIGH"]     + config_counts["HIGH"]     + custom_counts["HIGH"],
        "Risco Médio (MEDIUM)":      semgrep_counts["MEDIUM"]   + trivy_counts["MEDIUM"]   + secrets_counts["MEDIUM"]   + config_counts["MEDIUM"]   + custom_counts["MEDIUM"],
        "Monitoramento (LOW/INFO)":  (semgrep_counts["LOW"] + semgrep_counts["INFO"] +
                                      trivy_counts["LOW"]   + trivy_counts["INFO"] +
                                      secrets_counts["LOW"] + secrets_counts["INFO"] +
                                      config_counts["LOW"]  + config_counts["INFO"] +
                                      custom_counts["LOW"]  + custom_counts["INFO"]),
    }
    for label, val in risks.items():
        if "CRITICAL" in label: c.setFillColor(SEV_COLORS["CRITICAL"])
        elif "HIGH" in label:   c.setFillColor(SEV_COLORS["HIGH"])
        elif "MEDIUM" in label: c.setFillColor(SEV_COLORS["MEDIUM"])
        else:                    c.setFillColor(SEV_COLORS["LOW"])
        c.drawString(MARGIN_L, y, f"{label}: {val}")
        y -= 14
    c.setFillColor(colors.black)

    sem_total = sum(semgrep_counts.values())
    tri_total = sum(trivy_counts.values())
    sec_total = sum(secrets_counts.values())
    cfg_total = sum(config_counts.values())
    cus_total = sum(custom_counts.values())

    avg = avg_cvss(trivy_vulns)
    y -= 6; c.setFont("Helvetica", FONT_M)
    c.drawString(MARGIN_L, y, f"Totais → Semgrep: {sem_total} | Trivy (CVEs): {tri_total} | Secrets: {sec_total} | Config: {cfg_total} | Custom: {cus_total}")
    y -= 14
    c.drawString(MARGIN_L, y, f"CVSS médio (quando disponível): {avg:.1f}" if avg is not None else "CVSS médio: N/A")
    y -= 12

    # Heatmap Semgrep x Trivy (CVEs)
    def draw_heatmap(c, sem_counts, tri_counts, title, origin_x, origin_y):
        c.setFont("Helvetica-Bold", FONT_L); c.setFillColor(colors.black)
        c.drawString(origin_x, origin_y + 150, title)

        grid_w, grid_h = 340, 110
        cell_w = grid_w / 5.0  # CRITICAL..INFO
        cell_h = grid_h / 2.0
        d = Drawing(grid_w, grid_h)

        max_val = max([*sem_counts.values(), *tri_counts.values(), 1])
        SEV_HEAT_TARGET = {
            "CRITICAL": SEV_COLORS["CRITICAL"],
            "HIGH":     ORANGE_DARK,
            "MEDIUM":   ORANGE_PRIMARY,
            "LOW":      colors.HexColor("#fed7aa"),
            "INFO":     SEV_COLORS["INFO"],
        }

        order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        for r, _src in enumerate(["Semgrep","Trivy (CVEs)"]):
            for c_idx, sev in enumerate(order):
                v = sem_counts[sev] if r == 0 else tri_counts[sev]
                intensity = (v / max_val) if max_val else 0.0
                base = colors.white; mix = SEV_HEAT_TARGET[sev]
                fill = colors.Color(
                    base.red   + (mix.red   - base.red)   * intensity,
                    base.green + (mix.green - base.green) * intensity,
                    base.blue  + (mix.blue  - base.blue)  * intensity
                )
                x = c_idx * cell_w; y2 = (1 - r) * cell_h
                rect = Rect(x, y2, cell_w - 3, cell_h - 3, strokeWidth=0.2,
                            strokeColor=colors.lightgrey, fillColor=fill)
                d.add(rect)
                label_color = colors.white if intensity >= 0.60 else colors.black
                d.add(String(x + cell_w/2 - 6, y2 + cell_h/2 - 5, str(v),
                             fontName="Helvetica", fontSize=FONT_S, fillColor=label_color))

        renderPDF.draw(d, c, origin_x, origin_y)

    draw_heatmap(c, semgrep_counts, trivy_counts, "Heatmap de Severidade (Semgrep × Trivy CVEs)", MARGIN_L, y - 150)
    draw_footer(c); c.showPage()

    # Visão Geral – Gráficos
    section_pages["Visão Geral – Gráficos"] = c.getPageNumber()
    y = PAGE_H - MARGIN_T
    y = draw_section_title(c, "Visão Geral – Gráficos", y)
    y -= 14

    # Comparativo Semgrep × Trivy (por severidade)
    draw_grouped_bars_by_severity(
        c, semgrep_counts, trivy_counts,
        "SAST × SCA por Severidade (cores = severidade)",
        MARGIN_L, y - 240, width=PAGE_W - MARGIN_L - MARGIN_R, height=240
    )
    y = y - 260

    # Barras Secrets (severidades)
    draw_bars_with_values_single(
        c, secrets_counts,
        "Severidades – Exposição de Segredos (Trivy)",
        MARGIN_L, y - 240, width=PAGE_W - MARGIN_L - MARGIN_R, height=240
    )
    draw_footer(c); c.showPage()

    # Semgrep – Tópicos
    section_pages["Vulnerabilidades – SAST"] = c.getPageNumber()
    draw_semgrep_topics(c, semgrep)

    # Trivy – Vulnerabilidades (CVEs)
    section_pages["Vulnerabilidades – SCA (Trivy)"] = c.getPageNumber()
    draw_trivy_topics(c, trivy_vulns)

    # Trivy – Secrets
    if trivy_secrets:
        section_pages["Exposição de Segredos – Trivy"] = c.getPageNumber()
        draw_secrets_topics(c, trivy_secrets)

    # Trivy – Config/IaC
    if trivy_config:
        section_pages["Misconfigurações – IaC/Config (Trivy)"] = c.getPageNumber()
        draw_config_topics(c, trivy_config)

    # Custom Review – Tópicos
    section_pages["Achados – Custom Review"] = c.getPageNumber()
    draw_custom_topics(c, custom)

    c.save()

    # Sumário (TOC) + merge
    toc_items = []
    for name, p in section_pages.items():
        # após a capa, o sumário é inserido; então cada seção desloca +1
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
