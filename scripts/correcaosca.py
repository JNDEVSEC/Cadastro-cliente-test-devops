import os
import json
import re
import time
import subprocess
import platform
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

# ==========================================================
# ENV
# ==========================================================
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
CAMINHO_GEMINI = os.getenv("CAMINHO_GEMINI")
MAX_CVES = int(os.getenv("MAX_CVES", 3))

SEVERIDADES_VALIDAS = {"HIGH", "CRITICAL"}

# ==========================================================
# GEMINI EXEC
# ==========================================================
def executar_gemini(prompt: str) -> str:
    if not CAMINHO_GEMINI or not os.path.exists(CAMINHO_GEMINI):
        return "❌ Caminho do Gemini CLI não encontrado."

    if platform.system() == "Windows":
        comando = ["cmd", "/c", CAMINHO_GEMINI]
    else:
        comando = [CAMINHO_GEMINI]

    resultado = subprocess.run(
        comando,
        input=prompt,
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "GEMINI_API_KEY": GEMINI_API_KEY},
    )

    if resultado.stdout:
        return resultado.stdout.strip()

    return f"⚠️ Nenhuma saída do Gemini. STDERR: {resultado.stderr.strip()}"

# ==========================================================
# TRIVY PARSER
# ==========================================================
def carregar_vulnerabilidades_trivy(caminho: str) -> pd.DataFrame:
    if not os.path.exists(caminho):
        print("❌ trivy.json não encontrado.")
        return pd.DataFrame()

    with open(caminho, "r", encoding="utf-8") as f:
        data = json.load(f)

    registros = []

    for result in data.get("Results", []):
        if result.get("Type") != "library":
            continue

        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "").upper()
            if sev not in SEVERIDADES_VALIDAS:
                continue

            registros.append({
                "CVE_ID": vuln.get("VulnerabilityID"),
                "Componente": vuln.get("PkgName"),
                "Descricao": vuln.get("Description", "Descrição não fornecida"),
                "Severidade": sev,
            })

    return pd.DataFrame(registros).drop_duplicates()

# ==========================================================
# IA
# ==========================================================
def consultar_gemini(cve_id, componente, descricao):
    prompt = f"""
Analise a vulnerabilidade abaixo e responda **em português**, SEM introduções.

CVE: {cve_id}
Componente: {componente}
Descrição: {descricao}

Responda exatamente nesta estrutura:
1. Impacto
2. Correção ou mitigação
3. Conclusão
"""
    return executar_gemini(prompt)

def separar_blocos(texto):
    blocos = re.findall(r"\d\.\s*(.*?)\s*(?=\d\.|$)", texto, re.DOTALL)
    blocos = [re.sub(r"\s+", " ", b).strip() for b in blocos]
    while len(blocos) < 3:
        blocos.append("Não identificado")
    return blocos[:3]

# ==========================================================
# MAIN
# ==========================================================
def main():
    df = carregar_vulnerabilidades_trivy("trivy.json")

    if df.empty:
        print("✅ Nenhuma vulnerabilidade HIGH / CRITICAL encontrada.")
        return

    df = df.head(MAX_CVES)

    relatorio = []
    print(f"🤖 Analisando {len(df)} vulnerabilidades com IA...\n")

    for _, row in df.iterrows():
        resposta = consultar_gemini(
            row["CVE_ID"],
            row["Componente"],
            row["Descricao"]
        )

        impacto, correcao, conclusao = separar_blocos(resposta)

        relatorio.append(f"""
🔐 CVE: {row["CVE_ID"]}
📦 Componente: {row["Componente"]}
🔥 Severidade: {row["Severidade"]}

🧨 Impacto:
{impacto}

🛠️ Correção:
{correcao}

✅ Conclusão:
{conclusao}
--------------------------------------------------
""")

        time.sleep(30)

    nome = f"Relatorio_Correcoes_SCA_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(nome, "w", encoding="utf-8") as f:
        f.write("\n".join(relatorio))

    print(f"✅ Relatório gerado: {nome}")

if __name__ == "__main__":
    main()
