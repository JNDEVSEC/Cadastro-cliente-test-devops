import os
import json
import requests
import subprocess
import tempfile
import shutil
import re
from datetime import datetime
from dotenv import load_dotenv
from packaging.version import Version, InvalidVersion

# ==================================================
# ENV
# ==================================================
load_dotenv()
CAMINHO_TRIVY = os.getenv("CAMINHO_TRIVY")
SEVERIDADES_VALIDAS = {"HIGH", "CRITICAL"}

# ==================================================
# HELPERS
# ==================================================
def inferir_proxima_versao_segura(versao: str) -> str:
    try:
        v = Version(versao)
        return f"{v.major}.{v.minor}.{v.micro + 1}"
    except InvalidVersion:
        return "Não informado"

# ==================================================
# NVD – BUSCAR / INFERIR VERSÃO SEGURA
# ==================================================
def obter_versao_nao_vulneravel_nvd(cve_id: str, versao_instalada: str | None = None) -> tuple[str, str]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        r = requests.get(url, params=params, timeout=20)
        if r.status_code != 200:
            return "Não informado", "NVD"

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "Não informado", "NVD"

        cve = vulns[0]["cve"]

        # 1️⃣ Tentativa por CPE range (preferencial)
        versoes = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        if match.get("versionEndExcluding"):
                            versoes.append(match["versionEndExcluding"])
                        elif match.get("versionEndIncluding"):
                            versoes.append(match["versionEndIncluding"])

        if versoes:
            return min(versoes), "NVD"

        # 2️⃣ Tentativa por referências (release notes, advisory)
        for ref in cve.get("references", []):
            url_ref = ref.get("url", "")
            m = re.search(r"(\d+\.\d+\.\d+)", url_ref)
            if m:
                return m.group(1), "REFERENCIA"

        # 3️⃣ Fallback heurístico (inferido)
        if versao_instalada and versao_instalada not in ["", "Desconhecida"]:
            return inferir_proxima_versao_segura(versao_instalada), "INFERIDA"

        return "Não informado", "NVD"

    except Exception:
        return "Não informado", "ERRO"

# ==================================================
# TRIVY
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
                instalada = v.get("InstalledVersion", "Desconhecida")
                fixed_trivy = v.get("FixedVersion")

                if fixed_trivy:
                    versao_segura = fixed_trivy
                    origem = "TRIVY"
                else:
                    versao_segura, origem = obter_versao_nao_vulneravel_nvd(
                        v.get("VulnerabilityID"),
                        instalada
                    )

                result.append({
                    "CVE": v.get("VulnerabilityID"),
                    "Componente": v.get("PkgName"),
                    "Versao_Instalada": instalada,
                    "Versao_Segura": versao_segura,
                    "Origem_Versao": origem,
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
    print("🚦 Iniciando correcaoscav2 (Trivy + NVD + Inferência)")
    main()
