#!/bin/bash

CERTPATH="./data/syssspy.pem"

echo "[*] Generating selfsigned certificate $CERTPATH"
mkdir -p "$(dirname $CERTPATH)"
openssl req -new -newkey rsa:4096 -x509 -keyout "$CERTPATH" -out "$CERTPATH" -days 36500 -nodes -subj "/C=DE/ST=BW/L=Tuebingen/O=SySS GmbH/OU=Pentest/CN=$(id -nu)-$(hostname)"

