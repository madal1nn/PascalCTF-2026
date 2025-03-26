FROM python:3.13-alpine

RUN adduser -D -s /bin/sh challenge

WORKDIR /home/challenge

COPY ./app/requirements.txt .
RUN pip install -r requirements.txt

COPY ./app .

USER challenge

ENTRYPOINT [ "python3", "app.py" ]
