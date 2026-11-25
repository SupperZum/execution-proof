FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap libseccomp2 python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/collector
COPY offline.py pod_verifier.py collector.py deliver.py tls_api.py verify_download.py ./
USER 65532:65532
ENTRYPOINT ["python3", "-B", "collector.py"]
