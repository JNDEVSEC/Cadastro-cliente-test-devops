# Base mais antiga para forçar CVEs
FROM alpine:3.12

# Segredos com padrões realistas
ENV GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDE \
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE \
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    DEBUG=true

USER root

RUN apk add --no-cache \
      openssl \
      busybox \
      curl \
      wget \
      git || true

RUN wget -qO- http://example.com/install.sh | sh || true
RUN mkdir -p /var/app && chmod 777 /var/app

WORKDIR /var/app
COPY . .
EXPOSE 8080
CMD ["sh", "-c", "echo App rodando como root; sleep 3600"]
