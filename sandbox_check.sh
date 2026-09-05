#!/bin/bash
echo "--- ROOT DIRECTORY ---"
ls -la /
echo -e "\n--- HOME DIRECTORY ---"
ls -la /home/pedro
echo -e "\n--- PROCESSES ---"
ps -ef
echo -e "\n--- MOUNTS ---"
mount | grep -E "/home|/proc|/sys"
