#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
command -v geoipupdate >/dev/null || {
  echo "geoipupdate is not installed.  Install the Ubuntu geoipupdate package first." >&2
  exit 1
}

printf 'MaxMind Account ID: '
read -r account_id
printf 'MaxMind license key: '
read -rs license_key
printf '\n'
[[ "$account_id" =~ ^[0-9]+$ ]] || { echo "Account ID must be numeric." >&2; exit 1; }
[[ ${#license_key} -ge 12 ]] || { echo "The license key appears incomplete." >&2; exit 1; }

install -d -o root -g root -m 0755 /var/lib/GeoIP
umask 0077
cat > /etc/GeoIP.conf <<EOF_CONFIG
AccountID $account_id
LicenseKey $license_key
EditionIDs GeoLite2-City GeoLite2-ASN
DatabaseDirectory /var/lib/GeoIP
EOF_CONFIG
chmod 0600 /etc/GeoIP.conf
unset license_key

geoipupdate
systemctl daemon-reload
systemctl enable --now edgewatch-geoip-update.timer
systemctl restart edgewatch-agent.service

printf '\nGeoIP databases installed.  EdgeWatch will update them weekly.\n'
ls -lh /var/lib/GeoIP/GeoLite2-City.mmdb /var/lib/GeoIP/GeoLite2-ASN.mmdb
