import os
import json
import re
import time
import subprocess
import platform
from datetime import datetime
from dotenv import load_dotenv

# =========================
# ENV
# =========================
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
CAMINHO_GEMINI = os.getenv("CAMINHO_GEMINI")
MAX_CVES = int(os.getenv("MAX_CVES", 3))
SEVERIDADES_VALIDAS = {"HIGH", "CRITICAL"}

# =========================
# GEMINI EXEC
# =========================
def executar_gemini(prompt: str) -> str:
    if not CAMINHO_GEMINI or not os.path.exists(CAMINHO_GEMINI):
        return "Caminho do Gemini CLI não encontrado."

    comando = ["cmd", "/c", CAMINHO_GEMINI] if platform.system() == "Windows" else [CAMINHO_GEMINI]

    resultado = subprocess.run(
        comando,
        input=prompt,
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "GEMINI_API_KEY": GEMINI_API_KEY},
    )

    return resultado.stdout.strip() if resultado.stdout else "Sem resposta da IA."

# =========================
# TRIVY PARSER
# =========================
def carregar_trivy():
    if not os.path.exists("trivy.json"):
        return []

    with open("trivy.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    achados = []

    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            if v.get("Severity", "").upper() in SEVERIDADES_VALIDAS:
                achados.append({
                    "CVE": v.get("VulnerabilityID"),
                    "Pacote": v.get("PkgName"),
                    "Descricao": v.get("Description", "")
                })

    return achados[:MAX_CVES]

# =========================
# MAIN
# =========================
def main():
    vulns = carregar_trivy()

    if not vulns:
        print("Nenhuma vulnerabilidade HIGH/CRITICAL para análise por IA.")
        return

    blocos = []

    for v in vulns:
        prompt = f"""
Analise a vulnerabilidade abaixo e responda em português.

CVE: {v['CVE']}
Componente: {v['Pacote']}
Descrição: {v['Descricao']}

Estrutura obrigatória:
1. Impacto
2. Correção ou mitigação
3. Conclusão
"""
        resposta = executar_gemini(prompt)

        partes = re.findall(r"\d\.\s*(.*?)\s*(?=\d\.|$)", resposta, re.DOTALL)
        while len(partes) < 3:
            partes.append("Não identificado")

        blocos.append(f"""
🔐 CVE: {v['CVE']}
📦 Componente: {v['Pacote']}

🧨 Impacto:
{partes[0]}

🛠️ Correção:
{partes[1]}

✅ Conclusão:
{partes[2]}
--------------------------------------------------
""")

        time.sleep(30)

    nome = f"Relatorio_Correcoes_SCA_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(nome, "w", encoding="utf-8") as f:
        f.write("\n".join(blocos))

    print(f"Relatório de correções gerado: {nome}")

if __name__ == "__main__":
    main()
