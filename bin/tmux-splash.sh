#!/bin/bash

if [[ "$(tty)" == "/dev/pts/1" && "$(echo $TMUX | wc -c)" -gt "1" ]]
then
    ip=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
echo ""
echo "$(hostname)" | figlet -f Bloody
echo ""
echo -e "Public IP: \033[0;34m$ip\033[0m"
echo -e "Instance: \033[0;34m$(hostname)\033[0m"
echo ""
fi
