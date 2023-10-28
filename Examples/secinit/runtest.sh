#!/bin/bash

OPEN=("/usr/bin/open")
LAUNCHCTL=("/bin/launchctl")

rm -rf ~/Library/Containers/com.apple.calculator

${LAUNCHCTL} kickstart -kp user/${UID}/com.apple.secinitd

${OPEN} /System/Applications/Calculator.app
