# KubeWarden agent
#
# The image carries bcc (BPF Compiler Collection), which compiles the
# eBPF program through LLVM at startup — so LLVM itself has to be in the
# image too. Hence the size (~450 MB). The alternative is moving to
# libbpf CO-RE and building the .o ahead of time, which is a separate
# task.
#
# IMPORTANT about kernel headers: bcc compiles against the HOST kernel,
# not the image. That is why /lib/modules and /usr/src are mounted from
# the node in the DaemonSet manifest — and the versions there must match
# the node's `uname -r`.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# Without this, print() gets stuck in a buffer: stdout in a container is
# a pipe, not a TTY, so Python accumulates output in 8 KB blocks.
# Messages never appear in `kubectl logs` until the buffer fills up.
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-bpfcc \
        python3-yaml \
        python3-kubernetes \
        bpfcc-tools \
        libbpfcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kubewarden

COPY main.py .
COPY bpf/ bpf/
COPY core/ core/
COPY policies/ policies/

# Policies can be overridden by mounting a ConfigMap over this path
ENTRYPOINT ["python3", "main.py"]
CMD ["--in-cluster", "--enforce"]
