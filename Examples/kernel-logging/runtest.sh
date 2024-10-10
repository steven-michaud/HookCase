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

# 'launchctl kickstart -k' no longer works as of macOS 14.4 :-(
PID=`${SUDO} ${LAUNCHCTL} kickstart -p system/com.apple.diagnosticd | cut -f 4`
${SUDO} kill -9 ${PID}

${OPEN} /System/Applications/Utilities/Console.app
