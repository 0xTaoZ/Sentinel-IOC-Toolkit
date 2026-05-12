#!/bin/bash
echo "[*] STEP 1: Running Python Engine..."
cd python-backend && python3 extractor.py

echo "[*] STEP 2: Launching Java Dashboard..."
cd ../java-frontend && javac SentinelDashboard.java && java SentinelDashboard
