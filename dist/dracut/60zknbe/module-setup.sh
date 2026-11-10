#!/bin/bash
# dracut module: unlock LUKS2 volumes bound with ZK-NBE during early boot.
#
# Install:  cp -r 60zknbe /usr/lib/dracut/modules.d/ && dracut -f
# Network:  the initramfs needs networking, e.g. add `ip=dhcp` (or a static ip=) to the
#           kernel command line. rd.neednet=1 is set by this module.

check() {
    require_binaries zknbe cryptsetup || return 1
    # Include automatically when the host has a bound volume, otherwise only on request.
    if [[ $hostonly ]]; then
        local dev
        for dev in $(blkid -t TYPE=crypto_LUKS -o device 2>/dev/null); do
            cryptsetup luksDump "$dev" 2>/dev/null | grep -q '^\s*[0-9]\+: zknbe$' && return 0
        done
    fi
    return 255
}

depends() {
    echo crypt systemd network
}

install() {
    inst_multiple zknbe cryptsetup
    # Needed only when the device secret is TPM-sealed.
    inst_multiple -o systemd-creds
    inst_libdir_file -o "libtss2-esys.so.*" "libtss2-rc.so.*" "libtss2-mu.so.*" "libtss2-tcti-device.so.*"
    # Name resolution for glibc builds (static musl builds resolve on their own).
    inst_libdir_file -o "libnss_dns.so.*" "libnss_files.so.*" "libresolv.so.*"

    inst_simple "$moddir/zknbe-askpass.path" "$systemdsystemunitdir/zknbe-askpass.path"
    inst_simple "$moddir/zknbe-askpass.service" "$systemdsystemunitdir/zknbe-askpass.service"
    $SYSTEMCTL -q --root "$initdir" add-wants cryptsetup.target zknbe-askpass.path

    mkdir -p "$initdir/etc/cmdline.d"
    echo "rd.neednet=1" > "$initdir/etc/cmdline.d/60zknbe.conf"
}
