FROM python:3.14-alpine

WORKDIR /app
RUN apk add --no-cache socat
ADD main.py .

ARG FLAG
RUN echo "${FLAG}" > flag.txt

ENV PYTHONUNBUFFERED=1

CMD ["socat", "-d", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:'python3 /app/main.py'"]