apt update
apt install -y software-properties-common ca-certificates
add-apt-repository -y universe
add-apt-repository -y multiverse
apt update

apt install -y build-essential clang llvm pkg-config \
  libelf-dev zlib1g-dev libcap-dev binutils-dev

apt install -y \
  build-essential make gcc g++ pkg-config \
  git autoconf automake libtool git

cat >/etc/apt/sources.list.d/jammy-kernel.list <<'EOF'
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
EOF

cat >/etc/apt/preferences.d/jammy-kernel.pref <<'EOF'
Package: linux-headers* linux-tools* linux-modules* linux-image* linux-cloud-tools* linux-buildinfo*
Pin: release n=jammy
Pin-Priority: 601
EOF

apt update

apt install -y linux-headers-5.15.0-136-generic linux-tools-5.15.0-136-generic

apt install -y \
  llvm-dev clang

# === libbpf (dnf: libbpf-devel) ===
apt install -y \
  libbpf-dev

# === json-c (dnf: json-c + json-c-devel) ===
apt install -y \
  libjson-c-dev


apt-get update
apt-get install -y clang llvm make linux-libc-dev libc6-dev

apt install -y tshark

apt install -y python3 python3-pip
#pip3 install --no-cache-dir flask prometheus-client
#python3 -m pip install --break-system-packages flask prometheus-client

python3 -m pip install --break-system-packages --ignore-installed \
  blinker==1.9.0 jinja2==3.1.6 werkzeug==3.1.3 flask==3.1.2 prometheus-client packaging

#python3 -m pip install --break-system-packages gdown

cd /opt/oai-gnb
git clone --depth 1 https://github.com/libbpf/libbpf
cd libbpf/src
make install



cd /opt/oai-gnb
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install


cd /opt/oai-gnb
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


#gdown --folder https://drive.google.com/drive/folders/1KmwoEt4HzlSvWlSLglPk1UJXdwf6Sx0-?usp=sharing


echo "✅ Ubuntu setup complete: headers, toolchain, libbpf, clang/llvm, json-c, tshark, and Python packages."
