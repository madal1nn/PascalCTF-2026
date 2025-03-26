CREATE TABLE IF NOT EXISTS mailbox (
	username VARCHAR(50) NOT NULL,
	domain VARCHAR(50) NOT NULL,
	password VARCHAR(100) NOT NULL,
	PRIMARY KEY (username, domain)
);

INSERT INTO mailbox (username, domain, password)
VALUES ('{MAILBOX_USERNAME}', '{MAILBOX_DOMAIN}', '{MAILBOX_PASSWORD}')
ON CONFLICT (username, domain) DO NOTHING;

INSERT INTO mailbox (username, domain, password)
VALUES ('sburra', '{MAILBOX_DOMAIN}', 'sburra')
ON CONFLICT (username, domain) DO NOTHING;
