import json
import argparse
import sys

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def severity_ge(a, b):
    return SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True, help="trivy-results.json")
    parser.add_argument("--fail-on", default="CRITICAL" or "HIGHT",
                        choices=SEVERITY_ORDER)
    args = parser.parse_args()

    with open(args.trivy, "r", encoding="utf-8") as f:
        data = json.load(f)

    failures = []

    for result in data.get("Results", []):
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities", [])

        for v in vulnerabilities:
            cve = v.get("VulnerabilityID")
            pkg = v.get("PkgName")
            installed = v.get("InstalledVersion")
            fixed = v.get("FixedVersion")
            severity = v.get("Severity")

            if not severity_ge(severity, args.fail_on):
                continue

            if fixed and fixed != installed:
                failures.append({
                    "target": target,
                    "package": pkg,
                    "installed": installed,
                    "fixed": fixed,
                    "cve": cve,
                    "severity": severity
                })

    if failures:
        print("\n❌ Vulnerabilidades com correção disponível encontradas:\n")

        for f in failures:
            print(
                f"- [{f['severity']}] {f['cve']} | "
                f"{f['package']} {f['installed']} → {f['fixed']} "
                f"({f['target']})"
            )

        sys.exit(1)

    print("✅ Nenhuma vulnerabilidade crítica com correção pendente encontrada.")

if __name__ == "__main__":
    main()
