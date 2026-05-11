import os
import re
import time
import requests
import pandas as pd
import subprocess
from datetime import datetime
from dotenv import load_dotenv

# 📦 Carrega variáveis de ambiente
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL")
CAMINHO_COMPONENTES = os.getenv("CAMINHO_COMPONENTES")
CAMINHO_GEMINI = os.getenv("CAMINHO_GEMINI")
CASE = os.getenv("CASE")
LINGUAGENS_FILTRADAS = set(os.getenv("LINGUAGENS", "").split(","))
 # Lista de termos genéricos que causam falsos positivos
termos_ambiguos = {"async", "core", "lib", "common", "base", "util"}
# 🌐 Parâmetros da API NVD
URL_CVES = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
PARAMS = {
    'lastModStartDate': '2025-09-22T00:00:00',
    'lastModEndDate': '2025-09-22T23:59:59',
    'resultsPerPage': 2000
}

# 🔧 Utilitários
def carregar_componentes(caminho: str) -> list:
    df = pd.read_excel(caminho, engine="openpyxl")
    todos_componentes = df.iloc[:, 0].dropna().tolist()

    componentes_filtrados = []
    for comp in todos_componentes:
        comp = comp.strip()
        if len(comp) <= 3 or comp.lower() in termos_ambiguos:
            continue

        linguagem = identificar_linguagem(comp)
        if linguagem in LINGUAGENS_FILTRADAS:
            componentes_filtrados.append(f"{linguagem}/{comp}")

    return componentes_filtrados

def identificar_linguagem(componente: str) -> str:
    nome = componente.strip().lower()

    # Verifica no npm
    try:
        r_npm = requests.get(f"https://registry.npmjs.org/{nome}", timeout=5)
        if r_npm.status_code == 200:
            return "npm"
    except:
        pass

    # Verifica no PyPI
    try:
        r_pypi = requests.get(f"https://pypi.org/pypi/{nome}/json", timeout=5)
        if r_pypi.status_code == 200:
            return "python"
    except:
        pass

    # Verifica no Maven Central
    try:
        r_maven = requests.get(f"https://search.maven.org/solrsearch/select?q={nome}&rows=1&wt=json", timeout=5)
        if r_maven.status_code == 200 and r_maven.json().get("response", {}).get("numFound", 0) > 0:
            return "java"
    except:
        pass

    return "desconhecida"

def consultar_api_nvd() -> list:
    resposta = requests.get(URL_CVES, PARAMS)
    if resposta.status_code != 200:
        print(f"❌ Erro na API NVD: {resposta.status_code}")
        print(f"🔧 Detalhes: {resposta.text}")
        return []
    return resposta.json().get("vulnerabilities", [])

def extrair_descricao(cve: dict) -> str:
    return next((d.get("value") for d in cve.get("descriptions", []) if "value" in d), "")

def cve_tem_severidade_alta(cve: dict) -> bool:
    metrics = cve.get("metrics", {})

    # CVSS 3.1 – Score A
    for metrica in metrics.get("cvssMetricV31", []):
        severidade = metrica.get("cvssData", {}).get("baseSeverity", "").upper()
        if severidade in ["HIGH", "CRITICAL"]:
            return True

    # CVSS 4.0 – Score B
    for metrica in metrics.get("cvssMetricV40", []):
        severidade = metrica.get("cvssData", {}).get("baseSeverity", "").upper()
        if severidade in ["HIGH", "CRITICAL"]:
            return True

    # CNA severity (quando NVD ainda não avaliou)
    severidade_cna = cve.get("cnaSeverity", "").upper()
    if severidade_cna in ["HIGH", "CRITICAL"]:
        return True

    return False

def filtrar_cves_relevantes(cves: list, componentes: list) -> pd.DataFrame:
    relevantes = []

    # Filtra componentes muito curtos ou ambíguos
    componentes_filtrados = [
        comp for comp in componentes
        if len(comp) > 3 and comp.lower() not in termos_ambiguos
    ]

    for item in cves:
        cve = item.get("cve", {})
        descricao = extrair_descricao(cve)
        if not descricao:
            continue

        if not cve_tem_severidade_alta(cve):
            continue



        # Verifica correspondência direta com componentes
        for comp in componentes_filtrados:
            nome_pacote = comp.split("/")[-1]
            padrao = rf"(?<!\w){re.escape(nome_pacote)}(?!\w)"


            if re.search(padrao, descricao, re.IGNORECASE) or nome_pacote.lower() in descricao.lower():
                relevantes.append({
                    "CVE_ID": cve.get("id"),
                    "Descricao_API": descricao,
                    "Componente_Alvo": comp
                })
                break
    
        if item.get("cve", {}).get("id") == "CVE-2025-27152":
            print("🔍 DEBUG - CVE encontrada:")
            print(item)
            
    return pd.DataFrame(relevantes).drop_duplicates(subset="CVE_ID")

def consultar_gemini(cve_id: str, componente: str, descricao: str) -> str:
    if not CAMINHO_GEMINI or not isinstance(CAMINHO_GEMINI, str) or not os.path.exists(CAMINHO_GEMINI):
        return "❌ Caminho do Gemini CLI não encontrado."

    prompt = f"""
Analise a seguinte vulnerabilidade e responda em português:

🔐 CVE: {cve_id}
📦 Componente afetado: {componente}
📄 Descrição: {descricao}

Responda com os seguintes tópicos numerados:
1. Impacto potencial
2. Correções ou mitigações recomendadas
3. Conclusão

Limitações:
- Fique atento pois pode haver componentes que ao consultar não têm relação direta, exemplo: 'Async' pode ser um componente ou apenas qualificar algo
- Seja claro, direto e tecnicamente preciso
- Não repita a descrição original
- Não inclua frases genéricas como “vou analisar” ou “com base na descrição”
- Retorne apenas o conteúdo da análise, sem introduções ou interações
- Não repita as perguntas do prompt
"""

    try:
        resultado = subprocess.run(
            ["cmd", "/c", CAMINHO_GEMINI],
            input=prompt,
            capture_output=True,
            encoding="utf-8"
        )
        resposta = resultado.stdout.strip() if resultado.stdout else f"⚠️ Nenhuma saída recebida. STDERR: {resultado.stderr.strip()}"

        if "1." not in resposta or "2." not in resposta:
            with open("respostas_gemini_incompletas.txt", "a", encoding="utf-8") as log:
                log.write(f"\n--- {cve_id} ({componente}) ---\n{resposta}\n")

        return resposta
    except Exception as e:
        return f"❌ Erro ao executar Gemini CLI: {e}"

def separar_resposta(texto: str) -> pd.Series:
    if not isinstance(texto, str):
        return pd.Series(["Não identificado"] * 3)

    texto = re.sub(r"(?i)data collection is disabled.*", "", texto)
    texto = re.sub(r"(?i)(okay|compreendido|i will analyze).*?(?=\d\.)", "", texto)
    texto = re.sub(r"(?i)How can I help you.*?(?=\d\.)", "", texto)
    texto = texto.strip()

    blocos = re.findall(r"\d\.\s*(.*?)\s*(?=\d\.|$)", texto, re.DOTALL)
    blocos = [re.sub(r"\s+", " ", b).strip() for b in blocos if b.strip()]

    # Fallback: tenta dividir por parágrafos se não houver blocos numerados
    if len(blocos) < 3:
        parags = [p.strip() for p in texto.split("\n") if p.strip()]
        blocos = parags[:3]

    while len(blocos) < 3:
        blocos.append("Não identificado")

    return pd.Series(blocos[:3])

def gerar_relatorio_texto(cve_id, componente, descricao, impacto, correcao, conclusao) -> str:
    return f"""
🔐 CVE: {cve_id}
📦 Componente afetado: {componente}

📄 Descrição da vulnerabilidade:
{descricao}

🧨 Impacto potencial:
{impacto}

🛠️ Correção recomendada:
{correcao}

✅ Conclusão:
{conclusao}
------------------------------------------------------------
"""

# 🚀 Execução principal
def main():
    CAMINHO_COMPONENTES = os.getenv("CAMINHO_COMPONENTES")
    if not CAMINHO_COMPONENTES or not isinstance(CAMINHO_COMPONENTES, str) or not os.path.exists(CAMINHO_COMPONENTES):
        print("❌ Caminho do arquivo de componentes não encontrado ou inválido.")
        return

    cves = consultar_api_nvd()
    if not cves:
        return
    componentes = carregar_componentes(CAMINHO_COMPONENTES)
    df = filtrar_cves_relevantes(cves, componentes)
    if df.empty:
        print("⚠️ Nenhuma vulnerabilidade relevante encontrada.")
        return

    print(f"\n🔎 Analisando {len(df)} CVEs com Gemini (limite: 2/min)...\n")
    respostas = []

    for _, row in df.iterrows():
        resposta = consultar_gemini(
            row["CVE_ID"],
            row["Componente_Alvo"],
            row["Descricao_API"]
        )

        respostas.append(resposta)

        with open("respostas_gemini_log.txt", "a", encoding="utf-8") as log:
            log.write(f"\n--- {row['CVE_ID']} ({row['Componente_Alvo']}) ---\n{resposta}\n")

        time.sleep(60)

    df["Resposta"] = respostas
    df[["Impacto Potencial", "Correções/Mitigações", "Conclusão"]] = pd.DataFrame(
        [separar_resposta(texto) for texto in respostas]
    )
    df["Descrição Vulnerabilidade"] = df["Descricao_API"]

    df_final = df[[
        "CVE_ID",
        "Componente_Alvo",
        "Descrição Vulnerabilidade",
        "Impacto Potencial",
        "Correções/Mitigações",
        "Conclusão"
    ]]

    nome_txt = f"Relatorio_CVEs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(nome_txt, "w", encoding="utf-8") as f:
        for _, row in df_final.iterrows():
            texto = gerar_relatorio_texto(
                row["CVE_ID"],
                row["Componente_Alvo"],
                row["Descrição Vulnerabilidade"],
                row["Impacto Potencial"],
                row["Correções/Mitigações"],
                row["Conclusão"]
            )
            f.write(texto)

    print(f"📝 Relatório em texto plano salvo: {nome_txt}")

if __name__ == "__main__":
    main()
