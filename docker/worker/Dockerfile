FROM python:3.6-slim

ARG maxmind_key

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    make \
    patch \
    git \
    qemu \
    qemu-system \
    openvpn \
    binutils \
    iprange \
    wget \
    tar \
    e2tools

RUN git clone --branch 5.9.8 https://github.com/radare/radare2 \
    && find radare2/ -name "*.py" -exec sed -i 's/time\.time_ns()/int(time.time()*1e9)/g' {} + \
    && radare2/sys/install.sh \
    && useradd -m lisa \
    && echo "Downloading LiSa Linux images ..." \
    && wget https://github.com/danieluhricek/linux-images/archive/v1.0.1.tar.gz \
    && tar -xzf v1.0.1.tar.gz \
    && mkdir -p /home/lisa/images \
    && mv /linux-images-1.0.1/* /home/lisa/images/ \
    && chown -R lisa:lisa /home/lisa/images

COPY --chown=lisa:lisa ./data /home/lisa/data
COPY --chown=lisa:lisa ./docker /home/lisa/docker
COPY --chown=lisa:lisa ./lisa /home/lisa/lisa
COPY --chown=lisa:lisa ./requirements.txt /home/lisa/requirements.txt

ENV PYTHONPATH /home/lisa

WORKDIR /home/lisa

RUN pip install -r requirements.txt \
    && iprange -j data/blacklists/* > data/ipblacklist \
    && ./docker/worker/maxmind.sh $maxmind_key \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    git \
    gcc \
    g++ \
    make \
    patch \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /radare2/.git

CMD ["./docker/worker/init.sh"]
