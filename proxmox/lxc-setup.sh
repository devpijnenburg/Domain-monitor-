#!/usr/bin/env bash
set -euo pipefail

LXC_VMID="${LXC_VMID:?LXC_VMID environment variable is required}"
TEMPLATE="local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
HOSTNAME="domain-monitor"
CORES=4
MEMORY=4096
DISK="local-lvm:40"
BRIDGE="vmbr0"

log() { echo "[lxc-setup] $*"; }

download_template_if_missing() {
    if ! pveam list local | grep -q "ubuntu-22.04-standard"; then
        log "Downloading Ubuntu 22.04 LXC template..."
        pveam update
        pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst
    fi
}

create_lxc() {
    log "Creating LXC container $LXC_VMID..."
    pct create "$LXC_VMID" "$TEMPLATE" \
        --hostname "$HOSTNAME" \
        --cores "$CORES" \
        --memory "$MEMORY" \
        --rootfs "$DISK" \
        --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
        --features "nesting=1" \
        --unprivileged 0 \
        --onboot 1
    log "Container $LXC_VMID created."
}

start_and_wait() {
    pct start "$LXC_VMID"
    log "Waiting for network in container $LXC_VMID..."
    for i in $(seq 1 30); do
        if pct exec "$LXC_VMID" -- ip -4 addr show eth0 2>/dev/null | grep -q "inet "; then
            log "Network ready."
            return 0
        fi
        sleep 2
    done
    echo "ERROR: Timed out waiting for network in LXC $LXC_VMID" >&2
    exit 1
}

install_docker() {
    log "Installing Docker and dependencies in container $LXC_VMID..."
    pct exec "$LXC_VMID" -- bash -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg python3 python3-pip cron

        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
            > /etc/apt/sources.list.d/docker.list

        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

        systemctl enable --now docker
        systemctl enable --now cron
    '
    log "Docker installed."
}

# --- Main ---

if pct status "$LXC_VMID" &>/dev/null; then
    log "Container $LXC_VMID already exists — skipping creation."
    STATUS=$(pct status "$LXC_VMID" | awk '{print $2}')
    if [ "$STATUS" != "running" ]; then
        log "Starting container $LXC_VMID..."
        pct start "$LXC_VMID"
        start_and_wait
    fi
else
    download_template_if_missing
    create_lxc
    start_and_wait
    install_docker
fi

log "LXC $LXC_VMID is ready."
