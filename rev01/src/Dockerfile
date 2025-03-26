FROM python:3.13-alpine

WORKDIR /srv

RUN pip install --no-cache-dir \
    pygyat

RUN apk add --no-cache socat

COPY main.gyat .

ENV PYTHONUNBUFFERED=1

CMD ["socat", "-d", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'pygyat /srv/main.gyat'"]