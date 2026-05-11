import os
import json
import requests
import subprocess
import tempfile
import shutil
import re
import time
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

def escolher_versao_segura_trivy(instalada: str, fixed_versions: str) -> str:
    try:
        instalada_v = Version(instalada)
        fixes = [Version(v.strip()) for v in fixed_versions.split(",") if v.strip()]
        candidatas = [v for v in fixes if v > instalada_v]
        return str(min(candidatas)) if candidatas else str(max(fixes))
    except Exception:
        return fixed_versions

# ==================================================
# NVD – CONSULTA OBRIGATÓRIA + LOG
# ==================================================
def obter_versao_nao_vulneravel_nvd(cve_id: str, versao_instalada: str) -> tuple[str, str]:
    print(f"🔎 [NVD] Consultando CVE {cve_id}...")
    inicio = time.time()

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        r = requests.get(url, params=params, timeout=30)
        duracao = round(time.time() - inicio, 2)
        print(f"⏱️ [NVD] Resposta em {duracao}s (HTTP {r.status_code})")

        if r.status_code != 200:
            return "Não informado", "NVD"

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return "Não informado", "NVD"

        cve = vulns[0]["cve"]

        # ✅ CPE RANGES
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
            print(f"✅ [NVD] Versão segura detectada: {min(versoes)}")
            return min(versoes), "OFICIAL (NVD)"

        # ✅ REFERENCES (release notes)
        for ref in cve.get("references", []):
            m = re.search(r"(\d+\.\d+\.\d+)", ref.get("url", ""))
            if m:
                print(f"✅ [NVD] Versão extraída de referência: {m.group(1)}")
                return m.group(1), "OFICIAL (REFERENCIA)"

        # ✅ FALLBACK
        print("⚠️ [NVD] Nenhuma versão explícita encontrada")
        return inferir_proxima_versao_segura(versao_instalada), "⚠️ INFERIDA"

    except Exception as e:
        duracao = round(time.time() - inicio, 2)
        print(f"❌ [NVD] Erro após {duracao}s: {e}")
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

# ==================================================
# CORE LOGIC
# ==================================================
def extrair_vulnerabilidades(sbom: dict) -> list:
    result = []

    for r in sbom.get("Results", []):
        for v in r.get("Vulnerabilities", []) or []:
            if v.get("Severity", "").upper() in SEVERIDADES_VALIDAS:
                instalada = v.get("InstalledVersion", "Desconhecida")
                componente = v.get("PkgName")

                # ✅ TRIVY (sempre coletar)
                versao_trivy = None
                if v.get("FixedVersion"):
                    versao_trivy = escolher_versao_segura_trivy(
                        instalada,
                        v["FixedVersion"]
                    )

                # ✅ NVD (SEMPRE consultar)
                versao_nvd, origem_nvd = obter_versao_nao_vulneravel_nvd(
                    v.get("VulnerabilityID"),
                    instalada
                )

                # ✅ DECISÃO FINAL
                if versao_trivy:
                    versao_final = versao_trivy
                    origem = "✅ OFICIAL (TRIVY)"
                else:
                    versao_final = versao_nvd
                    origem = origem_nvd

                result.append({
                    "CVE": v.get("VulnerabilityID"),
                    "Componente": componente,
                    "Versao_Instalada": instalada,
                    "Versao_Segura": versao_final,
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
            print("✅ Nenhuma vulnerabilidade HIGH/CRITICAL")
            return

        gerar_relatorio_json(vulns)

    finally:
        shutil.rmtree(temp)

if __name__ == "__main__":
    print("🚦 Iniciando correcaoscav2 (TRIVY + NVD COMPROVADA)")
    main()
