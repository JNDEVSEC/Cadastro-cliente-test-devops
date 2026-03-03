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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

REPORT_PATH = "security-report.pdf"

SEM_GREP_JSON = "semgrep.json"
CUSTOM_JSON = "custom-review.json"
TRIVY_IMG_SARIF = "trivy-image.sarif"
TRIVY_FS_SARIF = "trivy-fs.sarif"

def load_json(path: str) -> Any:
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
            # Trivy costuma colocar severidade nos rules/properties ou tags; fallback para mapear level->severity
            sev = None
            # Tente extrair severidade do rule
            props = rule.get("properties", {}) if isinstance(rule, dict) else {}
            sev = (props.get("security-severity") or props.get("problem.severity") or props.get("severity") or "").upper()
            if not sev:
                # Mapeamento de nível SARIF para severidade aproximada
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

def summarize_trivy_sarif(path: str) -> Dict[str, int]:
    results = sarif_results(path)
    # sumariza por level (error/warning/note)
    counts = {"error": 0, "warning": 0, "note": 0}
    for r in results:
        lvl = r.get("level", "note")
        if lvl in counts:
            counts[lvl] += 1
    return counts

def sev_color(level: str):
    COLORS = {
        "CRITICAL": colors.Color(0.6, 0, 0),
        "HIGH": colors.Color(0.8, 0.2, 0.2),
        "MEDIUM": colors.Color(0.9, 0.6, 0.1),
        "LOW": colors.Color(0.3, 0.5, 0.8),
        "INFO": colors.Color(0.4, 0.4, 0.4),
        "note": colors.Color(0.4, 0.4, 0.4),
        "warning": colors.Color(0.9, 0.6, 0.1),
        "error": colors.Color(0.8, 0.2, 0.2),
    }
    return COLORS.get(level, colors.black)

def table_from_counts(title: str, counts: Dict[str, int], ordered_keys: List[str]) -> Table:
    data = [["Severidade", "Quantidade"]]
    for k in ordered_keys:
        data.append([k, str(counts.get(k, 0))])
    t = Table(data, colWidths=[7*cm, 4*cm])
    style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ("TEXTCOLOR", (0,0), (-1,0), colors.black),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
    ])
    for i, k in enumerate(ordered_keys, start=1):
        style.add("TEXTCOLOR", (0,i), (0,i), sev_color(k))
    t.setStyle(style)
    return t

def table_from_rows(rows: List[List[str]], col_widths=None) -> Table:
    t = Table(rows, colWidths=col_widths)
    style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ])
    t.setStyle(style)
    return t

def flatten_custom(js: Dict, limit: int = 100) -> List[List[str]]:
    rows = [["Rule ID", "Severity", "File", "Line", "Message"]]
    if not js:
        return rows
    for r in js.get("results", [])[:limit]:
        rows.append([
            str(r.get("rule_id","")),
            str(r.get("severity","")),
            str(r.get("file",""))[-80:],  # corta caminho para caber
            str(r.get("line","")),
            str(r.get("message",""))[:120],
        ])
    return rows

def flatten_trivy(results: List[Dict[str, Any]], limit: int = 50) -> List[List[str]]:
    """
    Constrói tabela para Trivy SARIF.
    Colunas: ID/Regra (CVE), Severidade, Local (arquivo/uri), Mensagem
    """
    rows = [["ID/Regra", "Severidade", "Local", "Mensagem"]]
    if not results:
        return rows
    # ordena por severidade (error > warning > note) e limita
    order = {"error": 0, "warning": 1, "note": 2}
    sorted_res = sorted(results, key=lambda x: order.get(x.get("level","note"), 2))
    for r in sorted_res[:limit]:
        rid = r.get("ruleId") or ""
        sev = r.get("severity") or r.get("level") or ""
        uri = (r.get("uri") or "")[-90:]
        msg = (r.get("message") or "")[:120]
        rows.append([rid, sev, uri, msg])
    return rows

def build_pdf():
    doc = SimpleDocTemplate(REPORT_PATH, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1", fontSize=16, leading=20, spaceAfter=10, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="H2", fontSize=13, leading=16, spaceAfter=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=13))
    flow = []

    # Cabeçalho
    flow.append(Paragraph("Relatório de Segurança — Pipeline CI", styles["H1"]))
    flow.append(Paragraph(datetime.utcnow().strftime("Gerado em %Y-%m-%d %H:%M:%S UTC"), styles["Body"]))
    flow.append(Spacer(1, 12))

    # Carregamento das fontes
    semgrep_js = load_json(SEM_GREP_JSON)
    custom_js = load_json(CUSTOM_JSON)

    # Sumário Semgrep
    flow.append(Paragraph("Semgrep — Sumário", styles["H2"]))
    if semgrep_js:
        sg_counts = summarize_semgrep(semgrep_js)
        flow.append(table_from_counts("Semgrep", sg_counts, ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]))
        flow.append(Spacer(1, 6))
        flow.append(Paragraph(f"Total de achados: {sum(sg_counts.values())}", styles["Body"]))
    else:
        flow.append(Paragraph("Arquivo semgrep.json não encontrado ou inválido.", styles["Body"]))
    flow.append(Spacer(1, 12))

    # Sumário Custom Review
    flow.append(Paragraph("Custom Security Review — Sumário", styles["H2"]))
    if custom_js:
        cv_counts = summarize_custom(custom_js)
        flow.append(table_from_counts("Custom", cv_counts, ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]))
        flow.append(Spacer(1, 6))
        flow.append(Paragraph(f"Total de achados: {sum(cv_counts.values())}", styles["Body"]))
    else:
        flow.append(Paragraph("Arquivo custom-review.json não encontrado ou inválido.", styles["Body"]))
    flow.append(Spacer(1, 12))

    # Trivy Image — Sumário + Detalhes
    flow.append(Paragraph("Trivy Image — Sumário (SARIF)", styles["H2"]))
    if os.path.exists(TRIVY_IMG_SARIF):
        tri_counts = summarize_trivy_sarif(TRIVY_IMG_SARIF)
        rows = [["Level", "Quantidade"]]
        for k in ["error","warning","note"]:
            rows.append([k, str(tri_counts.get(k, 0))])
        flow.append(table_from_rows(rows, col_widths=[6*cm, 4*cm]))
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Trivy Image — Detalhes (Top 50)", styles["H2"]))
        tri_results = sarif_results(TRIVY_IMG_SARIF)
        flow.append(table_from_rows(flatten_trivy(tri_results, limit=50), col_widths=[3.2*cm, 2.2*cm, 6.6*cm, 5.0*cm]))
    else:
        flow.append(Paragraph("Arquivo trivy-image.sarif não encontrado (scan de imagem pode ter sido pulado).", styles["Body"]))
    flow.append(Spacer(1, 12))

    # Trivy FS — Sumário + Detalhes
    flow.append(Paragraph("Trivy FS — Sumário (SARIF)", styles["H2"]))
    if os.path.exists(TRIVY_FS_SARIF):
        trfs_counts = summarize_trivy_sarif(TRIVY_FS_SARIF)
        rows = [["Level", "Quantidade"]]
        for k in ["error","warning","note"]:
            rows.append([k, str(trfs_counts.get(k, 0))])
        flow.append(table_from_rows(rows, col_widths=[6*cm, 4*cm]))
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Trivy FS — Detalhes (Top 50)", styles["H2"]))
        trfs_results = sarif_results(TRIVY_FS_SARIF)
        flow.append(table_from_rows(flatten_trivy(trfs_results, limit=50), col_widths=[3.2*cm, 2.2*cm, 6.6*cm, 5.0*cm]))
    else:
        flow.append(Paragraph("Arquivo trivy-fs.sarif não encontrado.", styles["Body"]))
    flow.append(Spacer(1, 12))

    # Detalhes — Custom Review (primeiros 100)
    flow.append(PageBreak())
    flow.append(Paragraph("Detalhes — Custom Security Review (primeiros 100)", styles["H2"]))
    if custom_js and custom_js.get("results"):
        rows = flatten_custom(custom_js, limit=100)
        flow.append(table_from_rows(rows, col_widths=[2.5*cm, 2.2*cm, 7.0*cm, 1.2*cm, 5.1*cm]))
    else:
        flow.append(Paragraph("Sem resultados para exibir.", styles["Body"]))

    doc.build(flow)

def main():
    build_pdf()
    print(f"[report] PDF gerado: {REPORT_PATH}")

if __name__ == "__main__":
    main()
