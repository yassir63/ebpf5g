FROM rockylinux:9

ARG KERNEL_VER=5.14.0-503.19.1.el9_5.x86_64


# Install the required packages
RUN dnf install -y bpftool kernel-devel git python3 python3-pip dos2unix clang llvm elfutils-libelf-devel libcap-devel gcc glibc-devel glibc-devel.i686 glibc-headers make perf nano iproute-tc
RUN dnf install -y https://download.rockylinux.org/stg/rocky/9/devel/x86_64/os/Packages/k/kernel-headers-${KERNEL_VER}.rpm
RUN dnf install -y https://download.rockylinux.org/stg/rocky/9/devel/x86_64/os/Packages/k/kernel-devel-${KERNEL_VER}.rpm
RUN dnf install 'dnf-command(config-manager)' -y
RUN dnf config-manager --set-enabled devel

RUN dnf install libbpf-devel json-c json-c-devel -y

RUN pip install flask prometheus_client


RUN dnf install -y jq
RUN curl -sSL -o /usr/local/bin/crictl https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.28.0/crictl-v1.28.0-linux-amd64.tar.gz && \
    tar -xzf /usr/local/bin/crictl -C /usr/local/bin && chmod +x /usr/local/bin/crictl

# Clone and install libbpf
# cd /ueransim

WORKDIR /app
COPY . .

RUN git clone --depth 1 https://github.com/libbpf/libbpf
WORKDIR libbpf/src
RUN make install


WORKDIR /app
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git
WORKDIR bpftool/src
RUN make install


WORKDIR /app
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


# Build userspace + BPF skeleton
RUN dos2unix Makefile && make

RUN chmod +x entrypoint-throughput.sh

# Runtime entry
CMD ["./entrypoint-throughput.sh"]
