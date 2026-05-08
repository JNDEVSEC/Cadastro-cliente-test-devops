
def montar_prompt(nome_produto: str, versao_atual: str, cve: str) -> str:
    """
    Cria um prompt que solicita exclusivamente a versão que corrige a vulnerabilidade.
    """
    prompt = f"""
Informe somente a versão que corrige a vulnerabilidade abaixo.

Produto: {nome_produto}
Versão atual: {versao_atual}
CVE: {cve}

Resposta esperada:
(apenas a versão corrigida, sem explicações)
"""
    return prompt


def consultar_modelo(prompt: str) -> str:
    """
    Função placeholder onde você integra o modelo de IA.
    Substitua a implementação pelo chamado real (OpenAI, Azure OpenAI, etc.).
    """
    # EXEMPLO DE RESPOSTA SIMULADA
    respostas_mock = {
        "sirv|CVE-2024-10855": "7.3.1"
    }

    chave = "sirv|CVE-2024-10855"
    return respostas_mock.get(chave, "versão não encontrada")


if __name__ == "__main__":
    nome_produto = input("Nome do produto: ").strip()
    versao_atual = input("Versão atual: ").strip()
    cve = input("CVE: ").strip()

    prompt = montar_prompt(nome_produto, versao_atual, cve)
    resposta = consultar_modelo(prompt)

    print(resposta)
