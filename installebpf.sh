dnf update -y

# Install the required packages
dnf install -y bpftool kernel-devel git clang llvm python3 python3-pip elfutils-libelf-devel libcap-devel gcc glibc-devel glibc-devel.i686 glibc-headers make perf nano iproute-tc
dnf install -y https://download.rockylinux.org/stg/rocky/9/devel/x86_64/os/Packages/k/kernel-headers-5.14.0-503.19.1.el9_5.x86_64.rpm
dnf install -y https://download.rockylinux.org/stg/rocky/9/devel/x86_64/os/Packages/k/kernel-devel-5.14.0-503.19.1.el9_5.x86_64.rpm
dnf install 'dnf-command(config-manager)' -y
dnf config-manager --set-enabled devel

dnf install libbpf-devel -y
dnf groupinstall "Development Tools" -y
dnf install llvm-devel clang-devel git -y

dnf install -y json-c json-c-devel
dnf install wireshark-cli -y
#pip install flask prometheus-client

python3 -m pip install --break-system-packages --ignore-installed \
  blinker==1.9.0 jinja2==3.1.6 werkzeug==3.1.3 flask==3.1.2

# Clone and install libbpf
#cd /ueransim
cd /opt/oai-gnb
git clone --depth 1 https://github.com/libbpf/libbpf
cd libbpf/src
make install


# Clone, build, and install bpftool
#cd /ueransim
cd /opt/oai-gnb
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install


# Generate vmlinux.h
#cd /ueransim
cd /opt/oai-gnb
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


echo "Installation of ebpf is complete. All tools are installed and ready to use."
