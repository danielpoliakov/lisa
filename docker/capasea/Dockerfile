FROM ubuntu:21.04

LABEL maintaner = "https://github.com/roaldi"

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install wget ca-certificates -y \
    && useradd -m capa

WORKDIR /home/capa

RUN wget "https://github.com/roaldi/CapaSea/releases/download/v0.5.0/CapaSea"

COPY ./docker/capasea/init.sh /home/capa/init.sh

CMD ["/home/capa/init.sh"]
