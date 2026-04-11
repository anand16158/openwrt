# Building traffic-classifier for Indio UM-325AX-V2

**Target:** `ipq50xx/generic`  
**Device:** `indio_um-325ax-v2`  
**Architecture:** `aarch64_cortex-a53` (ARM64)

## Option A: Build Inside This Source Tree

If this OpenWrt source tree **already has** ipq50xx target support (from
uCentral/TIP setup), you can build directly:

```bash
# On your Linux build host:
cd /path/to/openwrt-anand
git checkout openwrt-traffic-classifier

# Build packages
chmod +x build.sh
./build.sh package

# Or build full firmware
./build.sh firmware
```

## Option B: Add as Feed to Your uCentral Build Tree (Recommended)

If you have a **separate** uCentral/TIP build tree where you normally build
firmware for the Indio device, add this repo as a package feed:

### Step 1: Add Feed

In your **uCentral build tree** (not this repo):

```bash
cd /path/to/ucentral-build

# Add traffic-classifier as a feed
echo 'src-git tcfeed https://github.com/anand16158/openwrt-anand.git;openwrt-traffic-classifier' >> feeds.conf

# Update and install
./scripts/feeds update tcfeed
./scripts/feeds install -a -p tcfeed
```

### Step 2: Enable Packages

```bash
# Add to your diffconfig or run menuconfig
make menuconfig
```

Navigate to:
- **Network → traffic-classifier** → select as `<M>` (module)
- **LuCI → 3. Applications → luci-app-traffic-classifier** → select as `<M>` (module)

Or append to your diffconfig:
```
CONFIG_PACKAGE_traffic-classifier=m
CONFIG_PACKAGE_luci-app-traffic-classifier=m
```

### Step 3: Build Packages Only (Fast ~2 min)

```bash
make package/traffic-classifier/compile V=s -j$(nproc)
make package/luci-app-traffic-classifier/compile V=s -j$(nproc)
```

### Step 4: Find .ipk Files

```bash
find bin/ -name "traffic-classifier*.ipk" -o -name "luci-app-traffic-classifier*.ipk"
```

Expected output:
```
bin/packages/aarch64_cortex-a53/tcfeed/traffic-classifier_0.1.0-1_aarch64_cortex-a53.ipk
bin/packages/aarch64_cortex-a53/tcfeed/luci-app-traffic-classifier_0.1.0-1_all.ipk
```

### Step 5: Build Full Firmware (Bake In)

To include in the firmware image instead of installing separately:

Change `=m` to `=y` in your diffconfig:
```
CONFIG_PACKAGE_traffic-classifier=y
CONFIG_PACKAGE_luci-app-traffic-classifier=y
```

Then build as normal:
```bash
make -j$(nproc) V=s
```

The firmware image will be at:
```
bin/targets/ipq50xx/generic/openwrt-ipq50xx-indio_um-325ax-v2-squashfs-sysupgrade.tar
```

## Option C: Copy Packages Manually

If feeds don't work for your setup, copy the packages directly:

```bash
# From this repo, copy into your uCentral build tree:
cp -r package/network/services/traffic-classifier \
    /path/to/ucentral-build/package/network/services/

cp -r luci-app-traffic-classifier \
    /path/to/ucentral-build/package/
```

Then proceed with Step 2 above.

## Installing on the Device

### Method 1: SCP + opkg (for .ipk packages)

```bash
# From your build host:
scp traffic-classifier_*.ipk luci-app-traffic-classifier_*.ipk root@<device-ip>:/tmp/

# SSH into the device:
ssh root@<device-ip>

# Install
opkg install /tmp/traffic-classifier_*.ipk
opkg install /tmp/luci-app-traffic-classifier_*.ipk

# Enable and start
/etc/init.d/traffic-classifier enable
/etc/init.d/traffic-classifier start
```

### Method 2: sysupgrade (for full firmware)

```bash
scp bin/targets/ipq50xx/generic/openwrt-ipq50xx-indio_um-325ax-v2-squashfs-sysupgrade.tar \
    root@<device-ip>:/tmp/firmware.tar

ssh root@<device-ip>
sysupgrade /tmp/firmware.tar
```

### Method 3: Use install.sh

```bash
scp traffic-classifier_*.ipk luci-app-traffic-classifier_*.ipk install.sh root@<device-ip>:/tmp/
ssh root@<device-ip>
sh /tmp/install.sh
```

## Verifying the Installation

```bash
# Check daemon is running
ps | grep traffic-classifier

# Check logs
logread | grep traffic

# Test ubus API
ubus call traffic-classifier get_stats
ubus call traffic-classifier get_clients
ubus call traffic-classifier get_flows

# Access LuCI dashboard
# http://<device-ip>/cgi-bin/luci/admin/network/traffic-classifier
```

## Configuration

Edit `/etc/config/traffic-classifier` on the device:

```
config traffic-classifier 'main'
    option interface 'br-lan'
    option max_flows '4096'
    option qos_enabled '0'
    option telemetry_enabled '0'
    option telemetry_interval '60'
    option telemetry_path '/tmp/tc_telemetry.json'
    option data_capture_enabled '0'
    option data_capture_path '/tmp/tc_training.csv'
```

Key settings:
- `interface`: Network interface to capture on (usually `br-lan`)
- `qos_enabled`: Set to `1` to enable nftables DSCP marking
- `data_capture_enabled`: Set to `1` to log flows for ML retraining

## Troubleshooting

**Build fails with missing dependencies:**
```bash
# Make sure all feed packages are installed
./scripts/feeds update -a
./scripts/feeds install -a
```

**Package not found in menuconfig:**
```bash
# Check the feeds picked up the package
./scripts/feeds search traffic-classifier
# Should show: traffic-classifier
```

**Daemon won't start:**
```bash
# Check for missing libraries on device
opkg install libpcap libubox libubus libblobmsg-json libjson-c
/etc/init.d/traffic-classifier start
logread | grep traffic
```

**No traffic detected:**
```bash
# Verify interface exists
ip link show br-lan
# Try capturing manually
tcpdump -i br-lan -c 10
```
