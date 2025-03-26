FROM python:3.13-alpine

WORKDIR /srv
RUN apk add --no-cache socat

ADD requirements.txt /srv/requirements.txt
RUN pip install -r /srv/requirements.txt

ADD chall.py /srv/chall.py
ADD utils.py /srv/utils.py

ENV PYTHONUNBUFFERED=1

CMD ["socat", "-d", "TCP-LISTEN:42069,reuseaddr,fork", "EXEC:'python3 /srv/chall.py'"]
