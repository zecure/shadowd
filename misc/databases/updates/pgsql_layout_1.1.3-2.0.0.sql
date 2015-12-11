CREATE FUNCTION prepare_wildcard(input text) RETURNS text AS $$
DECLARE
	escape_us   text;
	escape_pc   text;
	wildcard1   text;
	unescape_ar text;
	wildcard2   text;
BEGIN
	escape_us   := REPLACE(input, '_', '\_');
	escape_pc   := REPLACE(escape_us, '%', '\%');
	wildcard1   := REPLACE(escape_pc, '*', '{WILDCARD}');
	unescape_ar := REPLACE(wildcard1, '\{WILDCARD}', '*');
	wildcard2   := REPLACE(unescape_ar, '{WILDCARD}', '%');

	RETURN wildcard2;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION is_flooding(input_profile_id int, input_client_ip text) RETURNS int AS $$
BEGIN
	RETURN (SELECT 1 FROM
		(SELECT COUNT(requests.id) AS request_count FROM requests WHERE
		requests.mode != 3 AND requests.client_ip = input_client_ip AND requests.profile_id
		= input_profile_id AND requests.date > NOW() - ((SELECT profiles.flooding_timeframe
		FROM profiles WHERE profiles.id = input_profile_id) || ' second')::INTERVAL) r WHERE
		r.request_count >= (SELECT profiles.flooding_threshold FROM profiles WHERE
		profiles.id = input_profile_id));
END;
$$ LANGUAGE plpgsql;

ALTER TABLE profiles DROP COLUMN learning_enabled;
ALTER TABLE profiles ADD COLUMN integrity_enabled smallint NOT NULL DEFAULT 0;
ALTER TABLE profiles ADD COLUMN flooding_enabled smallint NOT NULL DEFAULT 1;
ALTER TABLE profiles ADD COLUMN mode int NOT NULL DEFAULT 1;
ALTER TABLE profiles RENAME threshold TO blacklist_threshold;
ALTER TABLE profiles RENAME flooding_time TO flooding_timeframe;
ALTER TABLE profiles ADD COLUMN cache_outdated smallint NOT NULL DEFAULT 0;
ALTER TABLE parameters RENAME COLUMN total_rules TO total_whitelist_rules;
ALTER TABLE requests ADD COLUMN total_integrity_rules INT NOT NULL DEFAULT 0;
ALTER TABLE requests ADD COLUMN resource text NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN locale text NOT NULL DEFAULT '';
ALTER TABLE requests DROP COLUMN learning;
ALTER TABLE requests ADD COLUMN mode INT NOT NULL DEFAULT 0;

INSERT INTO blacklist_filters VALUES (111, '(?:\{\s*\w+\s*:\s*[+-]?\s*\d+\s*:.*\})', 8, 'Detects serialized PHP objects');
UPDATE blacklist_filters SET rule = '(?:(?<!\w)(?:\.(?:ht(?:access|passwd|group))|(?:/etc/([./]*)(?:passwd|shadow|master\.passwd))|(?:apache|httpd|lighttpd)\.conf)\\b)', impact = 4, description = 'Finds sensible file names (Unix)' WHERE id = 12;
UPDATE blacklist_filters SET rule = '(?:(^(\s*)\||\|(\s*)$))' WHERE id = 104;
UPDATE blacklist_filters SET rule = '(?:(?<!\w)(boot\.ini|global\.asa)\b)', impact = 4, description = 'Finds sensible file names (Win)' WHERE id = 109;
UPDATE whitelist_filters SET description = 'Numeric (extended)' WHERE id = 2;

DELETE FROM tags_filters;
DELETE FROM tags;

INSERT INTO tags VALUES (1, 'xss');
INSERT INTO tags VALUES (2, 'win');
INSERT INTO tags VALUES (3, 'unix');
INSERT INTO tags VALUES (4, 'id');
INSERT INTO tags VALUES (5, 'lfi');
INSERT INTO tags VALUES (6, 'rfe');
INSERT INTO tags VALUES (7, 'sqli');
INSERT INTO tags VALUES (8, 'spam');
INSERT INTO tags VALUES (9, 'dos');
INSERT INTO tags VALUES (11, 'exec');
INSERT INTO tags VALUES (12, 'asm');
INSERT INTO tags VALUES (13, 'php');
INSERT INTO tags VALUES (14, 'perl');
INSERT INTO tags VALUES (15, 'python');

INSERT INTO tags_filters VALUES (1, 1);
INSERT INTO tags_filters VALUES (1, 2);
INSERT INTO tags_filters VALUES (1, 3);
INSERT INTO tags_filters VALUES (1, 4);
INSERT INTO tags_filters VALUES (1, 5);
INSERT INTO tags_filters VALUES (1, 6);
INSERT INTO tags_filters VALUES (1, 7);
INSERT INTO tags_filters VALUES (1, 8);
INSERT INTO tags_filters VALUES (1, 9);
INSERT INTO tags_filters VALUES (5, 10);
INSERT INTO tags_filters VALUES (4, 11);
INSERT INTO tags_filters VALUES (5, 11);
INSERT INTO tags_filters VALUES (3, 12);
INSERT INTO tags_filters VALUES (4, 12);
INSERT INTO tags_filters VALUES (5, 12);
INSERT INTO tags_filters VALUES (1, 13);
INSERT INTO tags_filters VALUES (1, 14);
INSERT INTO tags_filters VALUES (1, 15);
INSERT INTO tags_filters VALUES (1, 16);
INSERT INTO tags_filters VALUES (1, 17);
INSERT INTO tags_filters VALUES (1, 18);
INSERT INTO tags_filters VALUES (1, 19);
INSERT INTO tags_filters VALUES (1, 20);
INSERT INTO tags_filters VALUES (1, 21);
INSERT INTO tags_filters VALUES (1, 22);
INSERT INTO tags_filters VALUES (1, 23);
INSERT INTO tags_filters VALUES (1, 24);
INSERT INTO tags_filters VALUES (1, 25);
INSERT INTO tags_filters VALUES (1, 26);
INSERT INTO tags_filters VALUES (1, 27);
INSERT INTO tags_filters VALUES (1, 28);
INSERT INTO tags_filters VALUES (1, 29);
INSERT INTO tags_filters VALUES (1, 30);
INSERT INTO tags_filters VALUES (1, 31);
INSERT INTO tags_filters VALUES (1, 32);
INSERT INTO tags_filters VALUES (1, 33);
INSERT INTO tags_filters VALUES (1, 34);
INSERT INTO tags_filters VALUES (1, 35);
INSERT INTO tags_filters VALUES (7, 35);
INSERT INTO tags_filters VALUES (1, 37);
INSERT INTO tags_filters VALUES (1, 38);
INSERT INTO tags_filters VALUES (1, 39);
INSERT INTO tags_filters VALUES (6, 39);
INSERT INTO tags_filters VALUES (7, 40);
INSERT INTO tags_filters VALUES (7, 41);
INSERT INTO tags_filters VALUES (7, 42);
INSERT INTO tags_filters VALUES (7, 43);
INSERT INTO tags_filters VALUES (7, 44);
INSERT INTO tags_filters VALUES (7, 45);
INSERT INTO tags_filters VALUES (7, 46);
INSERT INTO tags_filters VALUES (7, 47);
INSERT INTO tags_filters VALUES (7, 48);
INSERT INTO tags_filters VALUES (7, 49);
INSERT INTO tags_filters VALUES (7, 50);
INSERT INTO tags_filters VALUES (7, 51);
INSERT INTO tags_filters VALUES (7, 52);
INSERT INTO tags_filters VALUES (7, 53);
INSERT INTO tags_filters VALUES (7, 54);
INSERT INTO tags_filters VALUES (7, 55);
INSERT INTO tags_filters VALUES (7, 56);
INSERT INTO tags_filters VALUES (7, 57);
INSERT INTO tags_filters VALUES (11, 58);
INSERT INTO tags_filters VALUES (13, 58);
INSERT INTO tags_filters VALUES (11, 59);
INSERT INTO tags_filters VALUES (13, 59);
INSERT INTO tags_filters VALUES (11, 60);
INSERT INTO tags_filters VALUES (13, 60);
INSERT INTO tags_filters VALUES (1, 61);
INSERT INTO tags_filters VALUES (6, 61);
INSERT INTO tags_filters VALUES (1, 62);
INSERT INTO tags_filters VALUES (8, 63);
INSERT INTO tags_filters VALUES (5, 64);
INSERT INTO tags_filters VALUES (1, 65);
INSERT INTO tags_filters VALUES (9, 65);
INSERT INTO tags_filters VALUES (1, 68);
INSERT INTO tags_filters VALUES (1, 69);
INSERT INTO tags_filters VALUES (7, 70);
INSERT INTO tags_filters VALUES (1, 71);
INSERT INTO tags_filters VALUES (7, 72);
INSERT INTO tags_filters VALUES (2, 73);
INSERT INTO tags_filters VALUES (5, 73);
INSERT INTO tags_filters VALUES (12, 75);
INSERT INTO tags_filters VALUES (7, 76);
INSERT INTO tags_filters VALUES (12, 77);
INSERT INTO tags_filters VALUES (1, 100);
INSERT INTO tags_filters VALUES (1, 101);
INSERT INTO tags_filters VALUES (3, 102);
INSERT INTO tags_filters VALUES (11, 102);
INSERT INTO tags_filters VALUES (1, 103);
INSERT INTO tags_filters VALUES (11, 104);
INSERT INTO tags_filters VALUES (14, 104);
INSERT INTO tags_filters VALUES (11, 105);
INSERT INTO tags_filters VALUES (11, 106);
INSERT INTO tags_filters VALUES (13, 106);
INSERT INTO tags_filters VALUES (11, 107);
INSERT INTO tags_filters VALUES (13, 107);
INSERT INTO tags_filters VALUES (8, 108);
INSERT INTO tags_filters VALUES (2, 109);
INSERT INTO tags_filters VALUES (4, 109);
INSERT INTO tags_filters VALUES (5, 109);
INSERT INTO tags_filters VALUES (11, 110);
INSERT INTO tags_filters VALUES (13, 111);

CREATE TABLE integrity_rules (
	id			SERIAL primary key,
	profile_id	integer NOT NULL,
	caller		text NOT NULL,
	algorithm	text NOT NULL,
	digest		text NOT NULL,
	date		timestamp NOT NULL DEFAULT date_trunc('seconds', now()::timestamp),
	status		smallint NOT NULL,
	FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

CREATE INDEX ON integrity_rules (profile_id);
CREATE INDEX ON integrity_rules (caller);
CREATE INDEX ON integrity_rules (algorithm);
CREATE INDEX ON integrity_rules (digest);
CREATE INDEX ON integrity_rules (date);
CREATE INDEX ON integrity_rules (status);

CREATE TABLE hashes (
	id			SERIAL primary key,
	request_id	integer NOT NULL,
	algorithm	text NOT NULL,
	digest		text NOT NULL,
	FOREIGN KEY (request_id) REFERENCES requests (id) ON DELETE CASCADE
);

CREATE TABLE integrity_requests (
	rule_id		int NOT NULL,
	request_id	int NOT NULL,
	FOREIGN KEY (rule_id) REFERENCES integrity_rules (id) ON DELETE CASCADE,
	FOREIGN KEY (request_id) REFERENCES requests (id) ON DELETE CASCADE,
	PRIMARY KEY (rule_id, request_id)
);

UPDATE profiles SET flooding_timeframe = flooding_timeframe * 60;
