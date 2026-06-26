#script automatico per compilazione Kernel, setup BusyBox e avvio QEMU

set -e # Interrompe lo script in caso di errore

# ==========================================
# CONFIGURAZIONE (Modifica se necessario)
# ==========================================
KERNEL_DIR="linux" # Assicurati che questa sia la cartella dei sorgenti del tuo kernel
BUSYBOX_VER="1.36.1"
INITRAMFS_NAME="initramfs_busybox.cpio.gz"
TEST_FILE="test_rdtsc/rdtsc.bpf"
TEST_LOADER="test_rdtsc/rdtsc_loader"
KERNEL_DIR_ABS="$HOME/eBPF-dev/linux"
echo "=========================================="
echo " 1. Compilazione del Kernel x86_64"
echo "=========================================="
if [ -d "$KERNEL_DIR" ]; then
        cd $KERNEL_DIR

            # Ripristinato: Rigenera il config da zero ogni volta
                make x86_64_defconfig
                    # --- Abilita BPF ---
                        ./scripts/config --enable CONFIG_BPF
                        ./scripts/config --enable CONFIG_BPF_SYSCALL
                        ./scripts/config --enable CONFIG_BPF_JIT
                        ./scripts/config --enable CONFIG_NET          # richiesto da socket_filter
                        ./scripts/config --enable CONFIG_INET
                        ./scripts/config --enable CONFIG_BPF_EVENTS
                        ./scripts/config --enable CONFIG_DEBUG_INFO
                        ./scripts/config --disable CONFIG_DEBUG_INFO_REDUCED
                        ./scripts/config --enable CONFIG_DEBUG_INFO_BTF=y
                        ./scripts/config --enable CONFIG_BPF_JIT_ALWAYS_ON
                        # Rigenera il .config risolvendo le dipendenze automaticamente
                          make olddefconfig

                          make -j$(nproc)
                              cd ..
                          else
                            echo "Errore: Cartella $KERNEL_DIR non trovata. Modifica la variabile KERNEL_DIR nello script."
                            exit 1
                          fi





echo -e "\n=========================================="
echo " 2. Scaricamento e Compilazione BusyBox"
echo "=========================================="
if [ ! -d "busybox-${BUSYBOX_VER}" ]; then
        wget https://busybox.net/downloads/busybox-${BUSYBOX_VER}.tar.bz2
            tar -xjf busybox-${BUSYBOX_VER}.tar.bz2
fi

cd busybox-${BUSYBOX_VER}
make defconfig
# Forza la compilazione statica
sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
sed -i 's/.*CONFIG_STATIC.*/CONFIG_STATIC=y/' .config

# LDFLAGS="--static" è vitale per risolvere il kernel panic (error -2)
make -j$(nproc) LDFLAGS="--static"
make install
cd ..

echo -e "\n=========================================="
echo " 3. Creazione del RootFS e file init"
echo "=========================================="
sudo rm -rf my_rootfs
mkdir -p my_rootfs/{bin,sbin,etc,proc,sys,usr/bin,usr/sbin,dev}

# Copia i binari di BusyBox
cp -a busybox-${BUSYBOX_VER}/_install/* my_rootfs/

# Crea lo script di init
cat << 'EOF' > my_rootfs/init
#!/bin/sh

# Montaggio dei filesystem virtuali
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf/

ip link set lo up

echo -e "\n============================================="
echo -e " Benvenuto nella tua shell BusyBox per eBPF!"
echo -e "=============================================\n"

# Passa il controllo alla shell
exec /bin/sh
EOF

# Rende lo script eseguibile
chmod +x my_rootfs/init

echo "Compilztion BPF kernel side"
~/llvm-project/build/bin/clang \
        -target bpf -O2 -g \
    -I "$HOME/eBPF-dev/kernel-headers/include" \
    -I "$KERNEL_DIR_ABS/tools/lib" \
    -c test/${TEST_FILE}.c -o test/${TEST_FILE}.o

echo "opcode checks"
~/llvm-project/build/bin/llvm-objdump -d test/${TEST_FILE}.o | grep -E "rdtsc|f7"

gcc -static test/${TEST_LOADER}.c -o test/${TEST_LOADER} \
    -I "$KERNEL_DIR_ABS/tools/lib" \
    -L "$KERNEL_DIR_ABS/tools/lib/bpf" \
    -lbpf -lelf -lz

mkdir -p my_rootfs/bin/test_rdtsc
cp test/${TEST_FILE}.o my_rootfs/bin/${TEST_FILE}.o
cp test/${TEST_LOADER} my_rootfs/bin/${TEST_LOADER}

cp ~/eBPF-dev/bpftool_static/bootstrap/bpftool my_rootfs/bin/bpftool
chmod +x my_rootfs/bin/bpftool


chmod +x my_rootfs/bin/${TEST_LOADER}

# (Rimosso il blocco per test_istruction)

cd my_rootfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../${INITRAMFS_NAME}
cd ..

echo -e "\n=========================================="
echo " 4. Avvio di QEMU"
echo "=========================================="
echo "Per uscire da QEMU: Premi Ctrl+A, poi rilascia e premi X"
sleep 3

sudo qemu-system-x86_64 \
        -kernel ${KERNEL_DIR}/arch/x86/boot/bzImage \
            -initrd ${INITRAMFS_NAME} \
                -nographic \
                    -append "console=ttyS0" \
                    -cpu host \
                    -m 2G \
                        --enable-kvm
