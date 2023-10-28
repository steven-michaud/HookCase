#!/bin/bash

SUDO=("/usr/bin/sudo")
OPEN=("/usr/bin/open")
LAUNCHCTL=("/bin/launchctl")

abort() {
  printf "%s\n" "$@" >&2
  exit 1
}

${SUDO} -v
if [[ $? -ne 0 ]]
then
  abort "Incorrect password for sudo"
fi

${SUDO} ${LAUNCHCTL} kickstart -kp system/com.apple.diagnosticd

${OPEN} /System/Applications/Utilities/Console.app
