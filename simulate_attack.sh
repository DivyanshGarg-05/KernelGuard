#!/bin/bash

echo "[*] PHASE 1: Generating Normal System Baseline..."
echo "[*] Sending background noise to train the Isolation Forest..."

# Generate 20 rapid system events to hit the 15-event threshold
for i in {1..20}; do 
    ls -la /etc > /dev/null
    cat /etc/os-release > /dev/null
    curl -s --connect-timeout 1 https://1.1.1.1 > /dev/null
    sleep 0.2
done

echo "[*] Baseline generated."
echo "[*] Pausing for 6 seconds to allow the eBPF sliding window to aggregate and lock the model..."
sleep 6

echo "\n[!] PHASE 2: Simulating Ransomware Attack..."
echo "[!] Forcing massive anomalous disk I/O..."

# Trigger the volumetric anomaly
dd if=/dev/urandom of=dummy_malware.out bs=1M count=1000 status=progress

echo "\n[*] Simulation complete. Check your sensor terminal!"