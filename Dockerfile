FROM docker.io/library/debian:bullseye

RUN apt update && \
    apt upgrade -y && \
    apt install -y curl && \
    curl -o /etc/apt/sources.list.d/jpace121.list http://packages.jpace121.net/apt/jpace121.list && \
    curl -o /etc/apt/trusted.gpg.d/jpace121.asc http://packages.jpace121.net/apt/jpace121.asc && \
    apt update && \
    apt install -y mosquitto j7s-mosquitto-plugin && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["mosquitto"]