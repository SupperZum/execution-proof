FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN command -v nsenter && command -v sha384sum && command -v mktemp
COPY entrypoint.sh install-worker.sh worker.tar /opt/onb17/
ENTRYPOINT ["/bin/bash", "/opt/onb17/entrypoint.sh"]
