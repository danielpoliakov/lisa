FROM python:3.6-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && useradd -m lisa

COPY --chown=lisa:lisa ./data /home/lisa/data
COPY --chown=lisa:lisa ./docker /home/lisa/docker
COPY --chown=lisa:lisa ./lisa /home/lisa/lisa
COPY --chown=lisa:lisa ./requirements.txt /home/lisa/requirements.txt

ENV PYTHONPATH /home/lisa
ENV FLASK_APP /home/lisa/lisa/web_api/app.py

WORKDIR /home/lisa

RUN pip install -r requirements.txt \
    && touch data/ipblacklist \
    && touch data/geolite2databases/GeoLite2-ASN.mmdb \
    && touch data/geolite2databases/GeoLite2-City.mmdb \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

USER lisa

EXPOSE 5000

CMD ["uwsgi", "--ini", "docker/api/app.ini"]
