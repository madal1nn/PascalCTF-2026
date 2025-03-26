#!/bin/sh

set -xe

if [ ! -f /.setup_complete ]; then
	export TLS_CERT_PATH=${TLS_CERT_PATH:-/etc/ssl/private/cert.pem}
	export TLS_KEY_PATH=${TLS_KEY_PATH:-/etc/ssl/private/key.pem}
	export VMAIL_UID=${VMAIL_UID:-1000}
	export VMAIL_GID=${VMAIL_GID:-1000}
	export POSTGRES_PORT=${POSTGRES_PORT:-5432}
	export POSTGRES_USER=${POSTGRES_USER:-postfix}
	export POSTGRES_DB=${POSTGRES_DB:-postfix}

	if [ ! -f ${TLS_CERT_PATH} ]; then
		openssl req -x509 -keyout ${TLS_KEY_PATH} -out ${TLS_CERT_PATH} -noenc -subj "/CN=$(hostname)/" --days 3650 --addext "basicConstraints=CA:FALSE"
	fi


	if [ ! -d /var/mail/vhosts ]; then
		mkdir -p /var/mail/vhosts
	fi
	
	chown ${VMAIL_UID}:${VMAIL_GID} /var/mail/vhosts

	tmp=$(mktemp)
	sed -E 's/\{([A-Za-z_][A-Za-z0-9_]*)\}/\$\1/g' /etc/postfix/main.cf | envsubst > $tmp
	cat $tmp > /etc/postfix/main.cf
	rm $tmp

	set +e
	# Wait for PostgreSQL to be ready
	echo "Waiting for PostgreSQL at ${POSTGRES_HOST}:${POSTGRES_PORT} ..."
	i=0
	while [ $i -lt 60 ]; do
		i=$((i+1))
		PGPASSWORD=${POSTGRES_PASS} psql -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} -U ${POSTGRES_USER} -d ${POSTGRES_DB} -c 'SELECT 1;' >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			echo "PostgreSQL is ready."
			break
		fi
		sleep 1
	done
	if [ $i -ge 60 ]; then
		echo "PostgreSQL is not ready after 60 seconds. Exiting."
		exit 1
	fi

	# Render schema with environment-backed placeholders for base account
	tmp_schema=$(mktemp)
	sed -E 's/\{([A-Za-z_][A-Za-z0-9_]*)\}/\$\1/g' /schema.sql | \
	  MAILBOX_USERNAME="${MAILBOX_USERNAME:-sus}" \
	  MAILBOX_DOMAIN="${MAILBOX_DOMAIN:-skillissue.it}" \
	  MAILBOX_PASSWORD="${MAILBOX_PASSWORD:-test}" \
	  envsubst > "$tmp_schema"

	# Apply schema and stop on any SQL error
	PGPASSWORD=${POSTGRES_PASS} psql -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} -U ${POSTGRES_USER} -d ${POSTGRES_DB} -v ON_ERROR_STOP=1 -f "$tmp_schema"
	apply_rc=$?
	rm -f "$tmp_schema"
	set -e
	if [ $apply_rc -ne 0 ]; then
		echo "Failed to apply schema to ${POSTGRES_DB} at ${POSTGRES_HOST}:${POSTGRES_PORT}"
		exit 1
	fi

	tmp=$(mktemp)
	sed -E 's/\{([A-Za-z_][A-Za-z0-9_]*)\}/\$\1/g' /etc/dovecot/dovecot.conf | envsubst > $tmp
	cat $tmp > /etc/dovecot/dovecot.conf
	rm $tmp

	touch /.setup_complete
fi

exec supervisord -c /etc/supervisord.conf
