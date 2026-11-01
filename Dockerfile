#
# Spiderfoot Dockerfile
#
# http://www.spiderfoot.net
#
# Written by: Michael Pellon <m@pellon.io>
# Updated by: Chandrapal <bnchandrapal@protonmail.com>
# Updated by: Steve Micallef <steve@binarypool.com>
# Updated by: Steve Bate <svc-spiderfoot@stevebate.net>
#    -> Inspired by https://github.com/combro2k/dockerfiles/tree/master/alpine-spiderfoot
#
# Usage:
#
#   sudo docker build -t spiderfoot .
#   sudo docker run -p 5001:5001 --security-opt no-new-privileges spiderfoot
#
# Using Docker volume for spiderfoot data
#
#   sudo docker run -p 5001:5001 -v /mydir/spiderfoot:/var/lib/spiderfoot spiderfoot
#
# Using SpiderFoot remote command line with web server
#
#   docker run --rm -it spiderfoot sfcli.py -s http://my.spiderfoot.host:5001/
#
# Running spiderfoot commands without web server (can optionally specify volume)
#
#   sudo docker run --rm spiderfoot sf.py -h
#
# Running a shell in the container for maintenance
#   sudo docker run -it --entrypoint /bin/sh spiderfoot
#
# Running spiderfoot unit tests in container
#
#   sudo docker build -t spiderfoot-test --build-arg REQUIREMENTS=test/requirements.txt .
#   sudo docker run --rm spiderfoot-test -m pytest --flake8 .

FROM python:3.15-alpine AS build
ARG REQUIREMENTS=requirements.txt
RUN apk add --no-cache gcc git curl swig tinyxml-dev \
 musl-dev openssl-dev libffi-dev libxslt-dev libxml2-dev jpeg-dev \
 openjpeg-dev zlib-dev cargo rust
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin":$PATH
COPY $REQUIREMENTS requirements.txt ./
RUN pip install -U pip
RUN pip install -r "$REQUIREMENTS"
# Python-based scanners used by sfp_tool_* modules (run from the same venv)
RUN pip install dnstwist wafw00f snallygaster


# ---------------------------------------------------------------------------
# External tools used by the sfp_tool_* modules. They live in their own stage so
# the compilers and download tooling stay out of the final image.
# ---------------------------------------------------------------------------
FROM python:3.15-alpine AS tools
ARG NUCLEI_VERSION=3.11.1
ARG TRUFFLEHOG_VERSION=3.99.7
ARG TESTSSL_VERSION=v3.2.4
ARG WHATWEB_VERSION=v0.6.4
ARG BBOT_VERSION=3.0.2
RUN apk add --no-cache gcc git curl unzip make cmake perl linux-headers pkgconf musl-dev libffi-dev openssl-dev openssl-libs-static zlib-dev rust cargo uv
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python
RUN set -eux; mkdir -p /out/bin; \
    case "$(uname -m)" in x86_64) A=amd64;; aarch64) A=arm64;; *) echo unsupported arch; exit 1;; esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${A}.zip" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip nuclei -d /out/bin; \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${A}.tar.gz" | tar -xz -C /out/bin trufflehog; \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /out/nuclei-templates; \
    rm -rf /out/nuclei-templates/.git; \
    git clone --depth 1 --branch "${TESTSSL_VERSION}" https://github.com/drwetter/testssl.sh /out/testssl; \
    rm -rf /out/testssl/.git; \
    git clone --depth 1 --branch "${WHATWEB_VERSION}" https://github.com/urbanadventurer/WhatWeb /out/whatweb; \
    rm -rf /out/whatweb/.git; \
    git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /out/cmseek; \
    rm -rf /out/cmseek/.git; \
    git clone --depth 1 https://github.com/trailofbits/onesixtyone /tmp/onesixtyone; \
    make -C /tmp/onesixtyone || gcc -o /tmp/onesixtyone/onesixtyone /tmp/onesixtyone/onesixtyone.c; \
    cp /tmp/onesixtyone/onesixtyone /out/bin/onesixtyone
# BBOT needs Python < 3.15, so it gets its own Python 3.13 venv. Its blasthttp
# dependency only ships glibc wheels, so it is built from source here against
# the system OpenSSL (the sdist expects a vendored OpenSSL otherwise).
ENV OPENSSL_DIR=/usr OPENSSL_LIB_DIR=/usr/lib OPENSSL_INCLUDE_DIR=/usr/include
RUN uv venv -q --python 3.13 /opt/bbot \
 && uv pip install -q --python /opt/bbot/bin/python --no-binary blasthttp "bbot==${BBOT_VERSION}" \
 && uv pip install -q --python /opt/bbot/bin/python "baddns~=2.4.0" "badsecrets~=1.2.1" "markdown~=3.4.3" \
      "pycryptodome~=3.23.0" "pypdfium2~=5.0" "pyyaml~=6.0" "wafw00f~=2.3.1" numpy \
      asyncpg aiosqlite aiomysql sqlmodel "aiokafka~=0.12.0" "aio_pika~=9.5.0" nats-py neo4j "pymongo~=4.15"
# ^ pip dependencies BBOT modules declare (deps_pip); bbot runs with --no-deps
#   in SpiderFoot and cannot install them at scan time as an unprivileged user.


FROM python:3.15-alpine
WORKDIR /home/spiderfoot

# Place database and logs outside installation directory
ENV SPIDERFOOT_DATA /var/lib/spiderfoot
ENV SPIDERFOOT_LOGS /var/lib/spiderfoot/log
ENV SPIDERFOOT_CACHE /var/lib/spiderfoot/cache

# Run everything as one command so that only one layer is created
RUN apk --update --no-cache add musl openssl libxslt tinyxml libxml2 jpeg zlib openjpeg \
    nmap nmap-scripts nbtscan ruby bash procps coreutils bind-tools libstdc++ nodejs npm git \
    && npm install -g --no-fund --no-audit retire \
    && gem install --no-document getoptlong addressable resolv-replace observer drb base64 csv mutex_m \
    && addgroup spiderfoot \
    && adduser -G spiderfoot -h /home/spiderfoot -s /sbin/nologin \
               -g "SpiderFoot User" -D spiderfoot \
    && rm -rf /var/cache/apk/* \
    && rm -rf /lib/apk/db \
    && rm -rf /root/.cache \
    && mkdir -p $SPIDERFOOT_DATA || true \
    && mkdir -p $SPIDERFOOT_LOGS || true \
    && mkdir -p $SPIDERFOOT_CACHE || true \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_DATA \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_LOGS \
    && chown spiderfoot:spiderfoot $SPIDERFOOT_CACHE

COPY . .
COPY --from=build /opt/venv /opt/venv
COPY --from=tools /out/bin/ /usr/local/bin/
COPY --from=tools /out/nuclei-templates /opt/nuclei-templates
COPY --from=tools /out/testssl /opt/testssl
COPY --from=tools /out/whatweb /opt/whatweb
COPY --from=tools /out/cmseek /opt/cmseek
COPY --from=tools /opt/uv-python /opt/uv-python
COPY --from=tools /opt/bbot /opt/bbot
RUN ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot
# BBOT tries to apt/sudo-install "core dependencies" on first run, which cannot
# work as an unprivileged user. Pre-seed its cache marker so it skips that step.
RUN mkdir -p /home/spiderfoot/.bbot/cache \
 && touch "/home/spiderfoot/.bbot/cache/$(/opt/bbot/bin/python -c 'import mmh3, orjson; from bbot.core.helpers.depsinstaller.installer import DepsInstaller as D; print(mmh3.hash(orjson.dumps(D.CORE_DEPS, option=orjson.OPT_SORT_KEYS)))')" \
 && chown -R spiderfoot:spiderfoot /home/spiderfoot/.bbot
ENV PATH="/opt/venv/bin:$PATH"

USER spiderfoot

EXPOSE 5001

# Run the application.
CMD ["python", "sf.py", "-l", "0.0.0.0:5001"]
