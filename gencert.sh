#!/bin/bash

CERTPATH="./data/outis.pem"

echo "[*] Generating selfsigned certificate $CERTPATH"
mkdir -p "$(dirname $CERTPATH)"
openssl req -new -newkey rsa:4096 -x509 -keyout "$CERTPATH" -out "$CERTPATH" -days 36500 -nodes -subj "/CN=$(id -nu)-$(hostname)"

