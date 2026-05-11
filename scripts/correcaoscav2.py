import os
import json
import requests
import subprocess
import tempfile
import shutil
from datetime import datetime
from dotenv import load_dotenv

# ==================================================
# ENV
# ==================================================
load_dotenv()
CAMINHO_TRIVY = os.getenv("CAMINHO_TRIVY")
SEVERIDADES_VALIDAS = {"HIGH", "CRITICAL"}

# ==================================================
# NVD – BUSCAR VERSÃO NÃO VULNERÁVEL
# ==================================================
def obter_versao_nao_vulneravel_nvd(cve_id: str) -> str:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        r = requests.get(url, params=params, timeout=20)
        if r.status_code != 200:
            return "Não informado (erro NVD)"

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "Não informado"

        versoes = []

        for config in vulns[0]["cve"].get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        if match.get("versionEndExcluding"):
                            versoes.append(match["versionEndExcluding"])
                        elif match.get("versionEndIncluding"):
                            versoes.append(match["versionEndIncluding"])

        return min(versoes) if versoes else "Não informado"
    except Exception as e:
        return f"Erro NVD: {e}"

# ==================================================
# TRIVY – EXECUTAR E PARSEAR
# ==================================================
def executar_trivy_repo(repo_url: str, saida: str) -> bool:
    comando = [
        CAMINHO_TRIVY,
        "repo",
        repo_url,
        "--format", "json",
        "--output", saida
    ]

    resultado = subprocess.run(comando, capture_output=True, encoding="utf-8")
    return resultado.returncode == 0 and os.path.exists(saida)

def extrair_vulnerabilidades(sbom: dict) -> list:
    result = []

    for r in sbom.get("Results", []):
        for v in r.get("Vulnerabilities", []) or []:
            if v.get("Severity", "").upper() in SEVERIDADES_VALIDAS:
                fixed = v.get("FixedVersion")
                if not fixed:
                    fixed = obter_versao_nao_vulneravel_nvd(v.get("VulnerabilityID"))

                result.append({
                    "CVE": v.get("VulnerabilityID"),
                    "Componente": v.get("PkgName"),
                    "Versao_Instalada": v.get("InstalledVersion", "Desconhecida"),
                    "Versao_Segura": fixed,
                    "Severidade": v.get("Severity"),
                    "Descricao": v.get("Description", "")
                })

    return result

# ==================================================
# RELATÓRIO
# ==================================================
def gerar_relatorio_json(vulns: list):
    nome = f"relatorio_correcoes_nvd_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(nome, "w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=2, ensure_ascii=False)
    print(f"✅ Relatório NVD gerado: {nome}")

# ==================================================
# MAIN
# ==================================================
def main():
    repo = os.getenv("REPO_SCAN", "https://github.com/vercel/next.js")
    if not CAMINHO_TRIVY:
        print("❌ CAMINHO_TRIVY não definido")
        return

    temp = tempfile.mkdtemp(prefix="nvd-scan-")
    saida = os.path.join(temp, "trivy.json")

    try:
        if not executar_trivy_repo(repo, saida):
            print("❌ Falha Trivy")
            return

        with open(saida, "r", encoding="utf-8") as f:
            sbom = json.load(f)

        vulns = extrair_vulnerabilidades(sbom)
        if not vulns:
            print("✅ Nenhuma vulnerabilidade HIGH / CRITICAL")
            return

        gerar_relatorio_json(vulns)
    finally:
        shutil.rmtree(temp)

if __name__ == "__main__":
    print("🚦 Iniciando correcaoscav2 (Trivy + NVD)")
    main()
``
