FROM python:3.13-alpine

WORKDIR /srv
RUN apk add --no-cache socat
ADD main.py /srv/main.py
ADD requirements.txt /srv/requirements.txt
RUN pip install -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["socat", "-d", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:'python3 /srv/main.py'"]