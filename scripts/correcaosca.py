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
# GEMINI EXEC (AJUSTADO)
# =========================
def executar_gemini(prompt: str) -> str:
    if not CAMINHO_GEMINI or not os.path.exists(CAMINHO_GEMINI):
        return "Caminho do Gemini CLI não encontrado."

    # ✅ IMPORTANTE: --stdin para o Gemini receber o prompt
    if platform.system() == "Windows":
        comando = ["cmd", "/c", CAMINHO_GEMINI, "--stdin"]
    else:
        comando = [CAMINHO_GEMINI, "--stdin"]

    resultado = subprocess.run(
        comando,
        input=prompt,
        capture_output=True,
        text=True,
        env={**os.environ, "GEMINI_API_KEY": GEMINI_API_KEY},
    )

    if resultado.stdout and resultado.stdout.strip():
        return resultado.stdout.strip()

    return f"SEM_RESPOSTA_DA_IA\nSTDERR: {resultado.stderr.strip()}"

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
# PARSER MAIS ROBUSTO
# =========================
def extrair_secao(texto, titulo):
    padrao = rf"{titulo}:\s*(.*?)(?=\n[A-ZÁÉÍÓÚÇ][a-záéíóúç]+:|$)"
    m = re.search(padrao, texto, re.DOTALL | re.MULTILINE)
    return m.group(1).strip() if m else "Não identificado"

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
        # ✅ PROMPT AJUSTADO (menos frágil)
        prompt = f"""
Você é um analista de segurança.

Responda OBRIGATORIAMENTE em português e exatamente neste formato,
sem texto fora da estrutura:

Impacto:
<texto>

Correção:
<texto>

Conclusão:
<texto>

Vulnerabilidade:
CVE: {v['CVE']}
Componente: {v['Pacote']}
Descrição: {v['Descricao']}
"""
        resposta = executar_gemini(prompt)

        impacto = extrair_secao(resposta, "Impacto")
        correcao = extrair_secao(resposta, "Correção")
        conclusao = extrair_secao(resposta, "Conclusão")

        blocos.append(f"""
🔐 CVE: {v['CVE']}
📦 Componente: {v['Pacote']}

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
        f.write("\n".join(blocos))

    print(f"Relatório de correções gerado: {nome}")

if __name__ == "__main__":
    main()
