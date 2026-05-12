@echo off
title Sentinel-IOC Control Center

echo [*] STEP 1: Running Python Threat Intelligence Engine...
cd python-backend
python extractor.py

echo.
echo [*] STEP 2: Compiling and Launching Java Dashboard...
cd ../java-frontend
javac SentinelDashboard.java
java SentinelDashboard

echo.
echo [*] All systems active.
pause
