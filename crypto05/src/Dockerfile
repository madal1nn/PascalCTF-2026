FROM python:3.13-alpine

WORKDIR /srv
RUN apk add --no-cache socat
ADD service.py /srv/service.py
RUN chmod +x /srv/service.py

ENV PYTHONUNBUFFERED=1

CMD ["socat", "-d", "TCP-LISTEN:1339,reuseaddr,fork", "EXEC:/srv/service.py"]

