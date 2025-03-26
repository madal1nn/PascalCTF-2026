FROM alpine:latest

RUN apk add --no-cache openssl envsubst postgresql-client rsyslog supervisor postfix-pgsql postfix dovecot dovecot-pgsql dovecot-lmtpd

COPY root/ /

VOLUME ["/var/mail/vhosts"]
EXPOSE 465 587 993

ENTRYPOINT ["/entrypoint.sh"]
