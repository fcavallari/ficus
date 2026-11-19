#!/bin/bash
# guest-collect.sh: prints the guest's state after a run, one section per `=== name ===` line. lab-run.sh copies it into
# the guest and runs it with sudo after eslogger has been stopped, then splits the output into post-state/<name>.txt.
# This is ground truth for the persistence rules: what is registered to start, and what is running.
#
#   sudo bash guest-collect.sh

export LC_ALL=C
USER_NAME=${SUDO_USER:-admin}
USER_HOME=$(eval echo "~$USER_NAME")

section() { printf '=== %s ===\n' "$1"; }

section btm
sfltool dumpbtm 2>&1

section launchagents
ls -laR /Library/LaunchAgents /Library/LaunchDaemons "$USER_HOME/Library/LaunchAgents" 2>&1

section crontabs
echo "--- root"
crontab -l 2>&1
echo "--- $USER_NAME"
crontab -l -u "$USER_NAME" 2>&1

section processes
ps -axo pid,ppid,user,command 2>&1
