#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, PageBreak

REPORT_PATH = "security-report.pdf"

SEM_GREP_JSON = "semgrep.json"
CUSTOM_JSON = "custom-review.json"
TRIVY_IMG_SARIF = "trivy-image.sarif"
TRIVY_FS_SARIF = "trivy-fs.sarif"

def load_json(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def summarize_semgrep(js: Dict) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not js:
        return counts
    for r in js.get("results", []):
        sev = (r.get("extra", {}).get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

def summarize_custom(js: Dict) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    if not js:
        return counts
    for r in js.get("results", []):
        sev = (r.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

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
            rid = res.get("ruleId")
            level = res.get("level", "note")
            msg = (res.get("message", {}) or {}).get("text", "")
            locs = res.get("locations", []) or []
            uri = ""
            if locs:
                uri = (locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") or "")
            rule = rules_index.get(rid, {})
            props = rule.get("properties", {}) if isinstance(rule, dict) else {}
            sev = (props.get("security-severity") or props.get("problem.severity") or props.get("severity") or "").upper()
            if not sev:
                sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
                sev = sev_map.get(level, "LOW")
            out.append({
                "ruleId": rid or "",
                "level": level,
                "severity": sev,
                "message": msg,
                "uri": uri
            })
    return out

def bullet_items_for_semgrep(js: Dict, styles, limit=None) -> ListFlowable:
    bullets = []
    if not js:
        return ListFlowable(bullets, bulletType="bullet", start=None)
    results = js.get("results", [])
    # sem limite: listar todas
    for r in results[: (limit or len(results))]:
        rid = r.get("check_id", "")
        sev = (r.get("extra", {}).get("severity") or "").upper()
        file = r.get("path", "")
        line = r.get("start", {}).get("line", "")
        msg = r.get("extra", {}).get("message", "")
        text = f"<b>{rid}</b> — <font color='#{sev_color_hex(sev)}'>{sev}</font> — {file}:{line} — {escape_xml(msg)}"
        bullets.append(ListItem(Paragraph(text, styles["Body"]), leftIndent=12))
    return ListFlowable(bullets, bulletType="bullet", start=None)

def bullet_items_for_custom(js: Dict, styles, limit=None) -> ListFlowable:
    bullets = []
    if not js:
        return ListFlowable(bullets, bulletType="bullet", start=None)
    results = js.get("results", [])
    for r in results[: (limit or len(results))]:
        rid = r.get("rule_id", "")
        sev = (r.get("severity") or "").upper()
        file = r.get("file", "")
        line = r.get("line", "")
        msg = r.get("message", "")
        text = f"<b>{rid}</b> — <font color='#{sev_color_hex(sev)}'>{sev}</font> — {file}:{line} — {escape_xml(msg)}"
        bullets.append(ListItem(Paragraph(text, styles["Body"]), leftIndent=12))
    return ListFlowable(bullets, bulletType="bullet", start=None)

def bullet_items_for_trivy_sarif(path: str, styles, limit=None) -> ListFlowable:
    bullets = []
    results = sarif_results(path)
    for r in results[: (limit or len(results))]:
        rid = r.get("ruleId", "")
        sev = (r.get("severity") or r.get("level") or "").upper()
        uri = r.get("uri", "")
        msg = r.get("message", "")
        text = f"<b>{rid}</b> — <font color='#{sev_color_hex(sev)}'>{sev}</font> — {uri} — {escape_xml(msg)}"
        bullets.append(ListItem(Paragraph(text, styles["Body"]), leftIndent=12))
    return ListFlowable(bullets, bulletType="bullet", start=None)

def sev_color_hex(level: str) -> str:
    # cores aproximadas para texto colorido nos bullets
    COLORS = {
        "CRITICAL": "990000",
        "HIGH": "CC3333",
        "MEDIUM": "E6A100",
        "LOW": "4D80CC",
        "INFO": "666666",
        "ERROR": "CC3333",
        "WARNING": "E6A100",
        "NOTE": "666666",
    }
    return COLORS.get(level.upper(), "000000")

def escape_xml(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def build_pdf():
    doc = SimpleDocTemplate(REPORT_PATH, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    # Estilos
    styles.add(ParagraphStyle(name="H1", fontSize=16, leading=20, spaceAfter=10, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16, spaceAfter=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=13))

    flow = []
    # Cabeçalho
    flow.append(Paragraph("Relatório de Segurança — Pipeline CI", styles["H1"]))
    flow.append(Paragraph(datetime.utcnow().strftime("Gerado em %Y-%m-%d %H:%M:%S UTC"), styles["Body"]))
    flow.append(Spacer(1, 10))

    # === Semgrep (sumário + bullets) ===
    semgrep_js = load_json(SEM_GREP_JSON)
    if semgrep_js:
        counts = summarize_semgrep(semgrep_js)
        total = sum(counts.values())
        flow.append(Paragraph(f"Semgrep — {total} achados (CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}, INFO={counts['INFO']})", styles["H2"]))
        flow.append(bullet_items_for_semgrep(semgrep_js, styles))
        flow.append(Spacer(1, 8))

    # === Custom Security Review (sumário + bullets) ===
    custom_js = load_json(CUSTOM_JSON)
    if custom_js:
        counts = summarize_custom(custom_js)
        total = sum(counts.values())
        flow.append(Paragraph(f"Custom Security Review — {total} achados (CRITICAL={counts['CRITICAL']}, HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}, INFO={counts['INFO']})", styles["H2"]))
        flow.append(bullet_items_for_custom(custom_js, styles))
        flow.append(Spacer(1, 8))

    # Quebra de página antes de Trivy para melhorar a leitura se houver muito conteúdo
    flow.append(PageBreak())

    # === Trivy Image (bullets) — apenas se o arquivo existir ===
    if os.path.exists(TRIVY_IMG_SARIF):
        flow.append(Paragraph("Trivy Image — Achados", styles["H2"]))
        flow.append(bullet_items_for_trivy_sarif(TRIVY_IMG_SARIF, styles))
        flow.append(Spacer(1, 8))

    # === Trivy FS (bullets) — apenas se o arquivo existir ===
    if os.path.exists(TRIVY_FS_SARIF):
        flow.append(Paragraph("Trivy FS — Achados", styles["H2"]))
        flow.append(bullet_items_for_trivy_sarif(TRIVY_FS_SARIF, styles))
        flow.append(Spacer(1, 8))

    doc.build(flow)

def main():
    build_pdf()
    print(f"[report] PDF gerado: {REPORT_PATH}")

if __name__ == "__main__":
    main()
