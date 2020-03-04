FROM python:3.6-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    make \
    patch \
    git \
    qemu \
    openvpn \
    binutils \
    iprange \
    wget \
    tar \
    e2tools \
    && git clone https://github.com/radare/radare2 \
    && radare2/sys/install.sh \
    && useradd -m lisa \
    && echo "Downloading LiSa Linux images ..." \
    && wget https://github.com/danieluhricek/linux-images/archive/v1.0.1.tar.gz -q -O - | tar xz -C /home/lisa \
    && mv /home/lisa/linux-images-1.0.1 /home/lisa/images

COPY --chown=lisa:lisa ./data /home/lisa/data
COPY --chown=lisa:lisa ./docker /home/lisa/docker
COPY --chown=lisa:lisa ./lisa /home/lisa/lisa
COPY --chown=lisa:lisa ./requirements.txt /home/lisa/requirements.txt
COPY --chown=lisa:lisa ./tests /home/lisa/tests

ENV PYTHONPATH /home/lisa

WORKDIR /home/lisa

RUN pip install -r requirements.txt \
    && iprange -j data/blacklists/* > data/ipblacklist \
    && echo "Downloading MaxMind GeoLite databases ..." \
    && wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz -q -O - | tar xz -C data/geolite2databases \
    && wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz -q -O - | tar xz -C data/geolite2databases \
    && mv $(find ./data -name GeoLite2-City.mmdb) ./data/geolite2databases \
    && mv $(find ./data -name GeoLite2-ASN.mmdb) ./data/geolite2databases \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    git \
    gcc \
    g++ \
    make \
    patch \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /radare2/.git

USER lisa

CMD ["pytest", "tests"]
