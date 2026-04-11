#!/bin/bash
#
# Build script for openwrt-traffic-classifier
# Target: Indio UM-325AX-V2 (ipq50xx/generic)
#
# This script is meant for the uCentral/TIP OpenWiFi build system.
# Your OpenWrt source tree must already have ipq50xx target support
# (from the uCentral/TIP build environment).
#
# Prerequisites:
#   - Linux build host (VM or native)
#   - sudo apt install build-essential clang flex bison g++ gawk \
#       gcc-multilib g++-multilib gettext git libncurses5-dev libssl-dev \
#       python3-distutils python3-setuptools rsync swig unzip zlib1g-dev \
#       file wget curl
#   - The uCentral build environment with ipq50xx target already set up
#
# Usage:
#   Option 1 — Package only (fast, ~2 min):
#     ./build.sh package
#
#   Option 2 — Full firmware with traffic-classifier baked in:
#     ./build.sh firmware
#
#   Option 3 — Just configure (add package to .config):
#     ./build.sh config
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

TARGET="ipq50xx"
SUBTARGET="generic"
DEVICE="indio_um-325ax-v2"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[BUILD]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Sanity checks ────────────────────────────────────────────────

check_prereqs() {
    [ -f "rules.mk" ] || err "Run this script from the OpenWrt source root."
    [ -d "package/network/services/traffic-classifier" ] || \
        err "traffic-classifier package not found. Are you on the right branch?"

    # luci-app sits at repo root; OpenWrt only scans package/ for Makefiles.
    # Create a symlink so the build system finds it.
    if [ -d "luci-app-traffic-classifier" ] && \
       [ ! -e "package/luci-app-traffic-classifier" ]; then
        log "Symlinking luci-app-traffic-classifier into package/ tree..."
        ln -s "../../luci-app-traffic-classifier" "package/luci-app-traffic-classifier"
    fi

    if [ ! -d "target/linux/${TARGET}" ]; then
        warn "target/linux/${TARGET} not found in this tree."
        warn "The ipq50xx target comes from the uCentral/TIP build system."
        warn "Make sure you have set up the full uCentral build environment"
        warn "with the ipq50xx target and ipq807x_v5.4 feed before proceeding."
        echo ""
        echo "If you already have a separate uCentral build tree, you can either:"
        echo "  1. Copy package/network/services/traffic-classifier/ into that tree"
        echo "  2. Copy luci-app-traffic-classifier/ into that tree"
        echo "  3. Or add this repo as a feed (see below)"
        echo ""
        echo "To add as a feed in your uCentral build tree:"
        echo "  echo 'src-git tcfeed https://github.com/anand16158/openwrt-anand.git;openwrt-traffic-classifier' >> feeds.conf.default"
        echo "  ./scripts/feeds update tcfeed"
        echo "  ./scripts/feeds install -a -p tcfeed"
        echo ""
        exit 1
    fi
}

# ── Update feeds ─────────────────────────────────────────────────

update_feeds() {
    log "Updating feeds..."
    ./scripts/feeds update -a
    ./scripts/feeds install -a
    log "Feeds updated."
}

# ── Configure ────────────────────────────────────────────────────

configure() {
    log "Adding traffic-classifier to build config..."

    if [ ! -f ".config" ]; then
        warn "No .config found. Running make menuconfig first..."
        warn "Select: Target=${TARGET}, Subtarget=${SUBTARGET}, Device=${DEVICE}"
        make menuconfig
    fi

    # Append package selections if not already present
    grep -q "CONFIG_PACKAGE_traffic-classifier" .config 2>/dev/null || \
        echo "CONFIG_PACKAGE_traffic-classifier=m" >> .config

    grep -q "CONFIG_PACKAGE_luci-app-traffic-classifier" .config 2>/dev/null || \
        echo "CONFIG_PACKAGE_luci-app-traffic-classifier=m" >> .config

    make defconfig
    log "Configuration done."
    echo ""
    log "Verify with: grep traffic-classifier .config"
    grep "traffic-classifier" .config || true
}

# ── Build package only ───────────────────────────────────────────

build_package() {
    log "Compiling traffic-classifier package..."
    make package/traffic-classifier/compile V=s -j"$(nproc)" || \
        err "traffic-classifier compilation failed. Check output above."

    log "Compiling luci-app-traffic-classifier package..."
    make package/luci-app-traffic-classifier/compile V=s -j"$(nproc)" || \
        err "luci-app compilation failed. Check output above."

    log "Generating package index..."
    make package/index V=s 2>/dev/null || true

    echo ""
    log "Build complete! Finding .ipk files..."
    echo ""

    TC_IPK=$(find bin/ -name "traffic-classifier_*.ipk" 2>/dev/null | head -1)
    LUCI_IPK=$(find bin/ -name "luci-app-traffic-classifier_*.ipk" 2>/dev/null | head -1)

    if [ -n "${TC_IPK}" ]; then
        log "Daemon:    ${TC_IPK}"
    else
        warn "traffic-classifier .ipk not found!"
    fi

    if [ -n "${LUCI_IPK}" ]; then
        log "LuCI app:  ${LUCI_IPK}"
    else
        warn "luci-app .ipk not found!"
    fi

    echo ""
    log "Install on device:"
    echo "  scp ${TC_IPK} ${LUCI_IPK} root@<device-ip>:/tmp/"
    echo "  ssh root@<device-ip>"
    echo "  opkg install /tmp/traffic-classifier_*.ipk"
    echo "  opkg install /tmp/luci-app-traffic-classifier_*.ipk"
    echo "  /etc/init.d/traffic-classifier enable"
    echo "  /etc/init.d/traffic-classifier start"
}

# ── Build full firmware ──────────────────────────────────────────

build_firmware() {
    log "Building full firmware for ${DEVICE}..."
    log "This will take 1-3 hours on first build."
    echo ""

    make download
    make -j"$(nproc)" V=s || make -j1 V=s

    echo ""
    log "Firmware build complete!"
    echo ""

    SYSUPGRADE=$(find bin/targets/${TARGET}/${SUBTARGET}/ \
        -name "*${DEVICE}*sysupgrade*" 2>/dev/null | head -1)

    if [ -n "${SYSUPGRADE}" ]; then
        log "Firmware: ${SYSUPGRADE}"
        log "Size:     $(du -h "${SYSUPGRADE}" | cut -f1)"
        echo ""
        log "Flash to device:"
        echo "  scp ${SYSUPGRADE} root@<device-ip>:/tmp/firmware.tar"
        echo "  ssh root@<device-ip>"
        echo "  sysupgrade /tmp/firmware.tar"
    else
        warn "Sysupgrade image not found. Check bin/targets/${TARGET}/${SUBTARGET}/"
        ls -la "bin/targets/${TARGET}/${SUBTARGET}/" 2>/dev/null || true
    fi
}

# ── Main ─────────────────────────────────────────────────────────

echo "============================================================"
echo "  Traffic Classifier — Build for Indio UM-325AX-V2"
echo "  Target: ${TARGET}/${SUBTARGET}"
echo "============================================================"
echo ""

check_prereqs

case "${1:-package}" in
    config)
        update_feeds
        configure
        ;;
    package|pkg)
        update_feeds
        configure
        build_package
        ;;
    firmware|full)
        update_feeds
        configure
        build_firmware
        ;;
    *)
        echo "Usage: $0 {config|package|firmware}"
        echo ""
        echo "  config   — Just add traffic-classifier to .config"
        echo "  package  — Build .ipk packages only (fast)"
        echo "  firmware — Build full firmware image with package baked in"
        exit 1
        ;;
esac
