ARG COLLECTOR_IMAGE
FROM ${COLLECTOR_IMAGE}
COPY rootfs/opt/onb17/trusted/bin/gcp-execution-proof-verifier rootfs/opt/onb17/trusted/bin/gcp-tdx-hardware-verifier rootfs/opt/onb17/trusted/bin/gcp-tdx-bootstrap-history-verifier /opt/onb17/trusted/bin/
COPY rootfs/opt/onb17/trusted/lib/ /opt/onb17/trusted/lib/
COPY context/trusted-runtime-bins.sha384 /opt/onb17/trusted/manifest.sha384
USER 65531:65531
ENTRYPOINT ["python3", "-EsB", "/opt/collector/pod_verifier.py"]
