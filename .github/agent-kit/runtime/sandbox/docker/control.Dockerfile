# Egress proxy and credential gateway. These run outside the agent container.
# Build with the runtime/ folder as context.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
COPY sandbox/egress_proxy.py sandbox/gateway.py /opt/sandbox/
RUN chmod -R a+rX,go-w /opt/sandbox
USER 65534:65534
