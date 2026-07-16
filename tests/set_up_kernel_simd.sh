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
                        ./scripts/config --enable CONFIG_DEBUG_INFO_BTF
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

# Copia i biimdari di BusyBox
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

echo 1 > /proc/sys/net/core/bpf_jit_enable
echo 1 > /proc/sys/kernel/bpf_stats_enabled

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

KERNEL_DIR="linux"
KERNEL_DIR_ABS="$(cd "$KERNEL_DIR" && pwd)"
CLANG="$HOME/llvm-project/build/bin/clang"
SIMD_TEST_DIR="test"

echo "=========================================="
echo " Compilazione test SIMD AVX-512"
echo "=========================================="

# --- 2. Compila il programma BPF con clang modificato ---
echo "[*] Compilazione simd_xdp.bpf.c con clang modificato..."
$CLANG -target bpf -O2 -g \
        -I "$KERNEL_DIR_ABS/tools/lib" \
            -I "$KERNEL_DIR_ABS/usr/include" \
                -c "$SIMD_TEST_DIR/simd_xdp.bpf.c" \
                    -o "$SIMD_TEST_DIR/simd_xdp.bpf.o"

if [ $? -ne 0 ]; then
        echo "[-] ERRORE: compilazione simd_xdp.bpf.c fallita"
            echo "    Verifica che il clang modificato sia in $CLANG"
                exit 1
fi

# Verifica con objdump che ci siano gli opcode SIMD
echo "[*] Verifica bytecode generato..."
"$HOME/llvm-project/build/bin/llvm-objdump" -d "$SIMD_TEST_DIR/simd_xdp.bpf.o" | grep -q "simd_"
if [ $? -eq 0 ]; then
        echo "[+] Opcode SIMD 0xe7 trovati nel bytecode!"
            "$HOME/llvm-project/build/bin/llvm-objdump" -d "$SIMD_TEST_DIR/simd_xdp.bpf.o"
        else
                echo "[!] ATTENZIONE: opcode SIMD non trovati, il clang potrebbe non avere le modifiche"
fi

# --- 3. Compila il loader con gcc ---
echo "[*] Compilazione simd_loader.c..."
gcc -static "$SIMD_TEST_DIR/simd_loader.c" -o "$SIMD_TEST_DIR/simd_loader" \
        -I "$KERNEL_DIR_ABS/tools/lib" \
            -L "$KERNEL_DIR_ABS/tools/lib/bpf" \
                -lbpf -lelf -lz

if [ $? -ne 0 ]; then
        echo "[-] ERRORE: compilazione simd_loader.c fallita"
            echo "    Verifica che libbpf.a sia in $KERNEL_DIR_ABS/tools/lib/bpf/"
                exit 1
fi
echo "[+] Compilazione completata."

# --- 4. Copia nel rootfs ---
echo "[*] Copia nel rootfs..."
mkdir -p my_rootfs/bin/test_simd
cp "$SIMD_TEST_DIR/simd_xdp.bpf.o" my_rootfs/bin/test_simd/
cp "$SIMD_TEST_DIR/simd_loader"     my_rootfs/bin/test_simd/
chmod +x my_rootfs/bin/test_simd/simd_loader

echo "[+] Test SIMD pronto. In QEMU esegui:"
echo "    cd /bin/test_simd && ./simd_loader"
echo ""





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
