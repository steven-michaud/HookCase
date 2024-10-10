#!/bin/bash

OPEN=("/usr/bin/open")
LAUNCHCTL=("/bin/launchctl")

rm -rf ~/Library/Containers/com.apple.calculator

# 'launchctl kickstart -k' no longer works as of macOS 14.4 :-(
PID=`${LAUNCHCTL} kickstart -p user/${UID}/com.apple.secinitd | cut -f 4`
kill -9 ${PID}

${OPEN} /System/Applications/Calculator.app
