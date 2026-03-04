# Dockerfile (propósito: achados com Alpine)

# [MISCONFIG] Tag 'latest'
FROM alpine:latest

# [MISCONFIG] Secrets em ENV
ENV TOKEN=plaintext-12345 \
    API_KEY=hardcoded-abc-xyz \
    DEBUG=true

# [MISCONFIG] Usuário root (padrão)
USER root

# [VULN] Instala pacotes com versões possivelmente vulneráveis
# (As versões variam; ainda assim Trivy costuma apontar CVEs)
RUN apk add --no-cache \
      openssl \
      busybox \
      curl \
      wget \
      git || true

# [MISCONFIG] Executa script remoto sem verificação
RUN wget -qO- http://example.com/install.sh | sh || true

# [MISCONFIG] Permissões fracas
RUN mkdir -p /var/app && chmod 777 /var/app

WORKDIR /var/app
COPY . .

# [MISCONFIG] Porta exposta
EXPOSE 8080

# [MISCONFIG] Sem HEALTHCHECK
CMD ["sh", "-c", "echo App rodando como root; sleep 3600"]
