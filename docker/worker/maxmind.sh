#!/bin/sh

if [ $# -eq 1 ]; then
  echo "Setting up MaxMind databases."
  wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$1&suffix=tar.gz" -q -O - | tar xz -C data/geolite2databases
  wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$1&suffix=tar.gz" -q -O - | tar xz -C data/geolite2databases
  mv $(find ./data -name GeoLite2-City.mmdb) ./data/geolite2databases
  mv $(find ./data -name GeoLite2-ASN.mmdb) ./data/geolite2databases
else
  echo "No MaxMind key provided."
fi
