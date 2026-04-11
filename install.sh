#!/bin/sh
#
# Install script for traffic-classifier on Indio UM-325AX-V2
# Run ON the OpenWrt device (via SSH)
#
# Usage:
#   1. SCP .ipk files to the device:
#      scp traffic-classifier_*.ipk luci-app-traffic-classifier_*.ipk root@<device-ip>:/tmp/
#
#   2. SSH into the device and run:
#      sh /tmp/install.sh
#
#   OR install manually:
#      opkg install /tmp/traffic-classifier_*.ipk
#      opkg install /tmp/luci-app-traffic-classifier_*.ipk
#
set -e

echo "=== Traffic Classifier Installer ==="
echo ""

# Install dependencies (may already be present on uCentral images)
echo "[*] Installing dependencies..."
opkg update 2>/dev/null || echo "    Warning: opkg update failed (offline install?)"

for dep in libpcap libubox libubus libblobmsg-json libuci nftables; do
    if ! opkg list-installed | grep -q "^${dep} "; then
        echo "    Installing ${dep}..."
        opkg install "${dep}" 2>/dev/null || echo "    Warning: ${dep} not available"
    else
        echo "    ${dep} already installed"
    fi
done

echo ""
echo "[*] Installing traffic-classifier..."
if ls /tmp/traffic-classifier_*.ipk >/dev/null 2>&1; then
    opkg install /tmp/traffic-classifier_*.ipk --force-reinstall
else
    echo "    ERROR: /tmp/traffic-classifier_*.ipk not found!"
    exit 1
fi

echo ""
echo "[*] Installing luci-app-traffic-classifier..."
if ls /tmp/luci-app-traffic-classifier_*.ipk >/dev/null 2>&1; then
    opkg install /tmp/luci-app-traffic-classifier_*.ipk --force-reinstall
else
    echo "    Warning: LuCI app .ipk not found, skipping"
fi

echo ""
echo "[*] Enabling and starting daemon..."
/etc/init.d/traffic-classifier enable
/etc/init.d/traffic-classifier start

echo ""
echo "[*] Verifying..."
sleep 2

if pidof traffic-classifier >/dev/null 2>&1; then
    echo "    Daemon running (PID: $(pidof traffic-classifier))"
else
    echo "    Warning: daemon not running, check: logread | grep traffic"
fi

# Quick ubus test
echo ""
echo "[*] Testing ubus API..."
ubus call traffic-classifier get_stats 2>/dev/null && echo "    ubus OK" || \
    echo "    ubus not responding yet (may need a moment)"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Access the dashboard at: http://<device-ip>/cgi-bin/luci/admin/network/traffic-classifier"
echo ""
echo "Useful commands:"
echo "  logread | grep traffic     # View daemon logs"
echo "  ubus call traffic-classifier get_stats     # Check stats"
echo "  ubus call traffic-classifier get_clients   # List clients"
echo "  ubus call traffic-classifier get_flows     # Active flows"
echo "  /etc/init.d/traffic-classifier restart     # Restart daemon"
echo ""
