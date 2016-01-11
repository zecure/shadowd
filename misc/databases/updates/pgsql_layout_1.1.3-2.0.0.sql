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

UPDATE whitelist_filters SET description = 'Numeric (extended)' WHERE id = 2;

DELETE FROM tags_filters;
DELETE FROM tags;
DELETE FROM blacklist_filters;

INSERT INTO tags VALUES (1, 'xss');
INSERT INTO tags VALUES (2, 'win');
INSERT INTO tags VALUES (3, 'unix');
INSERT INTO tags VALUES (4, 'rce');
INSERT INTO tags VALUES (5, 'lfi');
INSERT INTO tags VALUES (6, 'rfi');
INSERT INTO tags VALUES (7, 'sqli');
INSERT INTO tags VALUES (8, 'spam');
INSERT INTO tags VALUES (9, 'dos');
INSERT INTO tags VALUES (10, 'php');
INSERT INTO tags VALUES (11, 'perl');
INSERT INTO tags VALUES (12, 'python');
INSERT INTO tags VALUES (13, 'xxe');
INSERT INTO tags VALUES (14, 'ldap');
INSERT INTO tags VALUES (15, 'bash');
INSERT INTO tags VALUES (16, 'id');
INSERT INTO tags VALUES (17, 'mysql');
INSERT INTO tags VALUES (18, 'pgsql');
INSERT INTO tags VALUES (19, 'sqlite');
INSERT INTO tags VALUES (20, 'mongo');
INSERT INTO tags VALUES (21, 'tsql');
INSERT INTO tags VALUES (22, 'mssql');
INSERT INTO tags VALUES (23, 'css');

INSERT INTO blacklist_filters VALUES (1, '\(\)\s*\{.*?;\s*\}\s*;', 9, 'Shellshock (CVE-2014-6271)');
INSERT INTO blacklist_filters VALUES (2, '\(\)\s*\{.*?\(.*?\).*?=>.*?\\''', 9, 'Shellshock (CVE-2014-7169)');
INSERT INTO blacklist_filters VALUES (3, '\{\{.*?\}\}', 4, 'Flask curly syntax');
INSERT INTO blacklist_filters VALUES (4, '\bfind_in_set\b.*?\(.+?,.+?\)', 6, 'Common MySQL function "find_in_set"');
INSERT INTO blacklist_filters VALUES (5, '["''].*?>', 3, 'HTML breaking');
INSERT INTO blacklist_filters VALUES (6, '\bsqlite_master\b', 7, 'SQLite information disclosure "sqlite_master"');
INSERT INTO blacklist_filters VALUES (7, '\bmysql.*?\..*?user\b', 7, 'MySQL information disclosure "mysql.user"');
INSERT INTO blacklist_filters VALUES (8, '#.+?\)["\s]*>', 5, 'HTML breaking');
INSERT INTO blacklist_filters VALUES (9, '[''"][,;\s]+\w*[\[\(]', 3, 'HTML breaking');
INSERT INTO blacklist_filters VALUES (10, '>.*?<\s*\/?[\w\s]+>', 3, 'Unquoted HTML breaking with closing tag');
INSERT INTO blacklist_filters VALUES (11, '\blocation\b.*?\..*?\bhash\b', 2, 'JavaScript "location.hash"');
INSERT INTO blacklist_filters VALUES (12, '\bwith\b\s*\(.+?\)[\s\w]+\(', 6, 'Self-contained payload');
INSERT INTO blacklist_filters VALUES (13, '(\b(do|while|for)\b.*?\([^)]*\).*?\{)|(\}.*?\b(do|while|for)\b.*?\([^)]*\))', 4, 'C-style loops');
INSERT INTO blacklist_filters VALUES (14, '[=(].+?\?.+?:', 2, 'C-style ternary operator');
INSERT INTO blacklist_filters VALUES (15, '\\u00[a-f0-9]{2}', 1, 'Octal entity');
INSERT INTO blacklist_filters VALUES (16, '\\x0*[a-f0-9]{2}', 1, 'Hex entity');
INSERT INTO blacklist_filters VALUES (17, '\\\d{2,3}', 1, 'Unicode entity');
INSERT INTO blacklist_filters VALUES (18, '\.\.[\/\\]', 4, 'Directory traversal');
INSERT INTO blacklist_filters VALUES (19, '%(c0\.|af\.|5c\.)', 4, 'Directory traversal unicode + urlencoding');
INSERT INTO blacklist_filters VALUES (20, '%2e%2e[\/\\]', 4, 'Directory traversal urlencoding');
INSERT INTO blacklist_filters VALUES (21, '%c0%ae[\/\\]', 4, 'Directory traversal unicode + urlencoding');
INSERT INTO blacklist_filters VALUES (22, '\.(ht(access|passwd|group))|(apache|httpd)\d?\.conf', 4, 'Common Apache files');
INSERT INTO blacklist_filters VALUES (23, '\/etc\/[.\/]*(passwd|shadow|master\.passwd)', 4, 'Common Unix files');
INSERT INTO blacklist_filters VALUES (24, '\bdata:.*?,', 2, 'Data URI scheme');
INSERT INTO blacklist_filters VALUES (25, ';base64|base64,', 2, 'Data URI scheme "base64"');
INSERT INTO blacklist_filters VALUES (26, 'php:\/\/filter', 6, 'PHP input/output stream filter');
INSERT INTO blacklist_filters VALUES (27, 'php:\/\/input', 6, 'PHP input stream');
INSERT INTO blacklist_filters VALUES (28, 'php:\/\/output', 6, 'PHP output stream');
INSERT INTO blacklist_filters VALUES (29, 'convert\.base64-(de|en)code', 6, 'PHP input/output stream filter "base64"');
INSERT INTO blacklist_filters VALUES (30, 'zlib\.(de|in)flate', 6, 'PHP input/output stream filter "zlib"');
INSERT INTO blacklist_filters VALUES (31, '@import\b', 3, 'CSS "import"');
INSERT INTO blacklist_filters VALUES (32, '\burl\s*\(.+?\)', 2, 'CSS pointer to resource');
INSERT INTO blacklist_filters VALUES (33, '\/\/.+?\/', 1, 'URL');
INSERT INTO blacklist_filters VALUES (34, '\)\s*\[', 2, 'JavaScript language construct');
INSERT INTO blacklist_filters VALUES (35, '<\?(?!xml\s)', 3, 'PHP opening tag');
INSERT INTO blacklist_filters VALUES (36, '%(HOME(DRIVE|PATH)|SYSTEM(DRIVE|ROOT)|WINDIR|USER(DOMAIN|PROFILE|NAME)|((LOCAL)?APP|PROGRAM)DATA)%', 2, 'Common Windows environment variable');
INSERT INTO blacklist_filters VALUES (37, '%\w+%', 2, 'Windows environment variable pattern');
INSERT INTO blacklist_filters VALUES (38, '\bunion\b.+?\bselect\b', 3, 'Common SQL command "union select"');
INSERT INTO blacklist_filters VALUES (39, '\bupdate\b.+?\bset\b', 3, 'Common SQL command "update"');
INSERT INTO blacklist_filters VALUES (40, '\bdrop\b.+?\b(database|table)\b', 3, 'Common SQL command "drop"');
INSERT INTO blacklist_filters VALUES (41, '\bdelete\b.+?\bfrom\b', 3, 'Common SQL command "delete"');
INSERT INTO blacklist_filters VALUES (42, '--.+?', 1, 'Common SQL comment syntax');
INSERT INTO blacklist_filters VALUES (43, '\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]', 5, 'MongoDB SQL commands');
INSERT INTO blacklist_filters VALUES (44, '\$\(.+?\)', 2, 'jQuery selector');
INSERT INTO blacklist_filters VALUES (45, '\/\*.*?\*\/', 3, 'C-style comment syntax');
INSERT INTO blacklist_filters VALUES (46, '<!-.+?-->', 3, 'XML comment syntax');
INSERT INTO blacklist_filters VALUES (47, '<base\b.+?\bhref\b.+?>', 6, 'Base URL');
INSERT INTO blacklist_filters VALUES (48, '<!(element|entity|\[CDATA)', 6, 'XML entity injections');
INSERT INTO blacklist_filters VALUES (49, '<(applet|object|embed|audio|video|img|svg)', 2, 'Common JavaScript injection points (media)');
INSERT INTO blacklist_filters VALUES (50, '<a\b.+?\bhref\b', 2, 'Common JavaScript injection points (links)');
INSERT INTO blacklist_filters VALUES (51, '<(form|button|input|keygen|textarea|select|option)', 4, 'Common JavaScript injection points (forms)');
INSERT INTO blacklist_filters VALUES (52, '<(html|body|meta|link|i?frame|script|map)', 4, 'Common JavaScript injection points');
INSERT INTO blacklist_filters VALUES (53, '(?<!\w)(boot\.ini|global\.asa|sam)\b', 4, 'Common Windows files');
INSERT INTO blacklist_filters VALUES (54, '\bon\w+\s*=', 3, 'HTML event handler');
INSERT INTO blacklist_filters VALUES (55, '\b(chrome|file):\/\/', 3, 'Local file inclusion');
INSERT INTO blacklist_filters VALUES (56, '&#?(\w+);', 2, 'HTML escaped character');
INSERT INTO blacklist_filters VALUES (57, '^(\s*)\||\|(\s*)$', 5, 'Perl command injection');
INSERT INTO blacklist_filters VALUES (58, '<!--\W*?#\W*?(cmd|echo|exec|include|printenv)\b', 6, 'Apache server-side include');
INSERT INTO blacklist_filters VALUES (59, '\{\s*\w+\s*:\s*[+-]?\s*\d+\s*:.*?\}', 5, 'Serialized PHP objects');
INSERT INTO blacklist_filters VALUES (60, '[\n\r]\s*\b(?:to|b?cc)\b\s*:.*?\@', 5, 'Email injection');
INSERT INTO blacklist_filters VALUES (61, '\bcall_user_func\b.*?\(.+?\)', 7, 'Critical PHP function "call_user_func"');
INSERT INTO blacklist_filters VALUES (62, '\bcreate_function\b.*?\(.+?\)', 7, 'Critical PHP function "create_function"');
INSERT INTO blacklist_filters VALUES (63, '\beval\b.*?(\(.+?\)|\{.+?\})', 4, 'Critical function "eval"');
INSERT INTO blacklist_filters VALUES (64, '\bexec\b.*?\(.+?\)', 4, 'Critical PHP function "exec"');
INSERT INTO blacklist_filters VALUES (65, '\bf(get|open|read|write)\b.*?\(.+?\)', 5, 'Critical PHP function "fopen/fget/fread/fwrite"');
INSERT INTO blacklist_filters VALUES (66, '\bfile_(get|put)_contents\b.*?\(.+?\)', 7, 'Critical PHP function "file_get_contents/file_put_contents"');
INSERT INTO blacklist_filters VALUES (67, '\bmove_uploaded_file\b.*?\(.+?\)', 7, 'Critical PHP function "move_uploaded_file"');
INSERT INTO blacklist_filters VALUES (68, '\bpassthru\b.*?\(.+?\)', 7, 'Critical PHP function "passthru"');
INSERT INTO blacklist_filters VALUES (69, '\bp(roc_)?open\b.*?\(.+?\)', 6, 'Critical PHP function "popen/proc_open"');
INSERT INTO blacklist_filters VALUES (70, '\breadfile\b.*?\(.+?\)', 5, 'Critical PHP function "readfile"');
INSERT INTO blacklist_filters VALUES (71, '\bshell_exec\b.*?\(.+?\)', 7, 'Critical PHP function "shell_exec"');
INSERT INTO blacklist_filters VALUES (72, '\bsystem\b.*?\(.+?\)', 5, 'Critical PHP function "system"');
INSERT INTO blacklist_filters VALUES (73, '\bpreg_(replace|match)\b.*?\(.+?\)', 7, 'Critical PHP function "preg_match/preg_replace"');
INSERT INTO blacklist_filters VALUES (74, '\binclude(_once)?\b.*?;', 4, 'Critical PHP function "include"');
INSERT INTO blacklist_filters VALUES (75, '\brequire(_once)?\b.*?;', 4, 'Critical PHP function "require"');
INSERT INTO blacklist_filters VALUES (76, '\{\s*\$\s*\{.+?\}\s*\}', 8, 'PHP complex curly syntax');
INSERT INTO blacklist_filters VALUES (77, '@(cc_on|set)\b', 3, 'Conditional compilation token');
INSERT INTO blacklist_filters VALUES (78, '\bfirefoxurl\s*:', 3, 'Firefox "firefoxurl" URI handler');
INSERT INTO blacklist_filters VALUES (79, '\bwyciwyg\s*:', 3, 'Firefox "wyciwyg" URI handler');
INSERT INTO blacklist_filters VALUES (80, '\bdocument\b.*?\.', 2, 'JavaScript attribute "document"');
INSERT INTO blacklist_filters VALUES (81, '\bwindow\b.*?\.', 2, 'JavaScript attribute "window"');
INSERT INTO blacklist_filters VALUES (82, '=\s*\w+\s*\+\s*[''"]', 1, 'Common concatenation pattern');
INSERT INTO blacklist_filters VALUES (83, '\+=\s*\(\s*[''"]', 1, 'Common concatenation pattern');
INSERT INTO blacklist_filters VALUES (84, '[''"]\s*\+\s*[''"]', 1, 'Common concatenation pattern');
INSERT INTO blacklist_filters VALUES (85, '\|\(\w+=', 3, 'LDAP');
INSERT INTO blacklist_filters VALUES (86, '\bfunction\b[^(]*\([^)]*\)', 3, 'Common function declaration');
INSERT INTO blacklist_filters VALUES (87, '\bbenchmark\b.*?\(.+?,.+?\)', 8, 'Blind MySQL "benchmark"');
INSERT INTO blacklist_filters VALUES (88, '\bsleep\b.*?\(.+?\)', 2, 'Blind SQL "sleep"');
INSERT INTO blacklist_filters VALUES (89, '\bload_file\b.*?\(.+?\)', 7, 'MySQL file disclosure "load_file"');
INSERT INTO blacklist_filters VALUES (90, '\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b', 7, 'MySQL file disclosure "load data"');
INSERT INTO blacklist_filters VALUES (91, '\bselect\b.*?\binto\b.*?\b(out|dump)file\b', 8, 'MySQL file write "into outfile"');
INSERT INTO blacklist_filters VALUES (92, '\b(group_)?concat(_ws)?\b.*?\(.+?\)', 3, 'MySQL function "concat"');
INSERT INTO blacklist_filters VALUES (93, '\binformation_schema\b', 5, 'MySQL information disclosure');
INSERT INTO blacklist_filters VALUES (94, '\bpg_sleep\b.*?\(.+?\)', 6, 'Blind PgSQL "pg_sleep"');
INSERT INTO blacklist_filters VALUES (95, '\bwaitfor\b.*?\b(delay|time(out)?)\b', 4, 'Blind TSQL "waitfor"');
INSERT INTO blacklist_filters VALUES (96, '\b(char_|bit_)?length\b.*?\(.+?\)', 2, 'Common SQL function "length"');
INSERT INTO blacklist_filters VALUES (97, '\b(un)?hex\b.*?\(.+?\)', 2, 'Common SQL function "hex/unhex"');
INSERT INTO blacklist_filters VALUES (98, '\b(from|to)_base64\b.*?\(.+?\)', 4, 'Common MySQL function "from_base64/to_base64"');
INSERT INTO blacklist_filters VALUES (99, '\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)', 3, 'Common SQL function "substr"');
INSERT INTO blacklist_filters VALUES (100, '\b(current_)?user\b.*?\(.*?\)', 2, 'Common SQL function "user"');
INSERT INTO blacklist_filters VALUES (101, '\bversion\b.*?\(.*?\)', 2, 'Common SQL function "version"');
INSERT INTO blacklist_filters VALUES (102, '@@.+?', 1, 'SQL system variable');
INSERT INTO blacklist_filters VALUES (103, '\boct\b.*?\(.+?\)', 2, 'Common SQL function "oct"');
INSERT INTO blacklist_filters VALUES (104, '\bord\b.*?\(.+?\)', 2, 'Common SQL function "ord"');
INSERT INTO blacklist_filters VALUES (105, '\bascii\b.*?\(.+?\)', 2, 'Common SQL function "ascii"');
INSERT INTO blacklist_filters VALUES (106, '\bbin\b.*?\(.+?\)', 2, 'Common SQL function "bin"');
INSERT INTO blacklist_filters VALUES (107, '\bcha?r\b.*?\(.+?\)', 2, 'Common SQL function "char"');
INSERT INTO blacklist_filters VALUES (108, '\bwhere\b.+?(\b(not_)?(like|regexp)\b|[=<>])', 2, 'Common SQL comparison "where"');
INSERT INTO blacklist_filters VALUES (109, '\bif\b.*?\(.+?,.+?,.+?\)', 2, 'Common SQL comparison "if"');
INSERT INTO blacklist_filters VALUES (110, '\b(ifnull|nullif)\b.*?\(.+?,.+?\)', 3, 'Common SQL comparison "ifnull"');
INSERT INTO blacklist_filters VALUES (111, '\bwhere\b.+?(\b(n?and|x?or|not)\b|(\&\&|\|\|))', 3, 'Common SQL comparison "where"');
INSERT INTO blacklist_filters VALUES (112, '\bcase\b.+?\bwhen\b.+?\bend\b', 4, 'Common SQL comparison "case"');
INSERT INTO blacklist_filters VALUES (113, '\bexec\b.+?\bxp_cmdshell\b', 9, 'MSSQL code execution "xp_cmdshell"');
INSERT INTO blacklist_filters VALUES (114, '\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)', 4, 'Common SQL command "create"');
INSERT INTO blacklist_filters VALUES (115, '\binsert\b.+?\binto\b.*?\bvalues\b.*?\(.+?\)', 5, 'Common SQL command "insert"');
INSERT INTO blacklist_filters VALUES (116, '\bselect\b.+?\bfrom\b', 3, 'Common SQL command "select"');
INSERT INTO blacklist_filters VALUES (117, '\bpg_user\b', 7, 'PgSQL information disclosure "pg_user"');
INSERT INTO blacklist_filters VALUES (118, '\bpg_database\b', 7, 'PgSQL information disclosure "pg_database"');
INSERT INTO blacklist_filters VALUES (119, '\bpg_shadow\b', 7, 'PgSQL information disclosure "pg_shadow"');
INSERT INTO blacklist_filters VALUES (120, '\b(current_)?database\b.*?\(.*?\)', 2, 'Common SQL function "database"');

INSERT INTO tags_filters VALUES (4, 1);
INSERT INTO tags_filters VALUES (15, 1);
INSERT INTO tags_filters VALUES (4, 2);
INSERT INTO tags_filters VALUES (15, 2);
INSERT INTO tags_filters VALUES (4, 3);
INSERT INTO tags_filters VALUES (16, 3);
INSERT INTO tags_filters VALUES (7, 4);
INSERT INTO tags_filters VALUES (17, 4);
INSERT INTO tags_filters VALUES (1, 5);
INSERT INTO tags_filters VALUES (7, 6);
INSERT INTO tags_filters VALUES (19, 6);
INSERT INTO tags_filters VALUES (7, 7);
INSERT INTO tags_filters VALUES (17, 7);
INSERT INTO tags_filters VALUES (1, 8);
INSERT INTO tags_filters VALUES (1, 9);
INSERT INTO tags_filters VALUES (1, 10);
INSERT INTO tags_filters VALUES (1, 11);
INSERT INTO tags_filters VALUES (1, 12);
INSERT INTO tags_filters VALUES (4, 13);
INSERT INTO tags_filters VALUES (1, 13);
INSERT INTO tags_filters VALUES (9, 13);
INSERT INTO tags_filters VALUES (4, 14);
INSERT INTO tags_filters VALUES (1, 14);
INSERT INTO tags_filters VALUES (4, 15);
INSERT INTO tags_filters VALUES (1, 15);
INSERT INTO tags_filters VALUES (4, 16);
INSERT INTO tags_filters VALUES (1, 16);
INSERT INTO tags_filters VALUES (4, 17);
INSERT INTO tags_filters VALUES (1, 17);
INSERT INTO tags_filters VALUES (5, 18);
INSERT INTO tags_filters VALUES (5, 19);
INSERT INTO tags_filters VALUES (5, 20);
INSERT INTO tags_filters VALUES (5, 21);
INSERT INTO tags_filters VALUES (5, 22);
INSERT INTO tags_filters VALUES (5, 23);
INSERT INTO tags_filters VALUES (3, 23);
INSERT INTO tags_filters VALUES (1, 24);
INSERT INTO tags_filters VALUES (1, 25);
INSERT INTO tags_filters VALUES (5, 26);
INSERT INTO tags_filters VALUES (4, 26);
INSERT INTO tags_filters VALUES (10, 26);
INSERT INTO tags_filters VALUES (4, 27);
INSERT INTO tags_filters VALUES (10, 27);
INSERT INTO tags_filters VALUES (1, 28);
INSERT INTO tags_filters VALUES (10, 28);
INSERT INTO tags_filters VALUES (5, 29);
INSERT INTO tags_filters VALUES (4, 29);
INSERT INTO tags_filters VALUES (10, 29);
INSERT INTO tags_filters VALUES (5, 30);
INSERT INTO tags_filters VALUES (4, 30);
INSERT INTO tags_filters VALUES (10, 30);
INSERT INTO tags_filters VALUES (1, 31);
INSERT INTO tags_filters VALUES (23, 31);
INSERT INTO tags_filters VALUES (1, 32);
INSERT INTO tags_filters VALUES (23, 32);
INSERT INTO tags_filters VALUES (6, 32);
INSERT INTO tags_filters VALUES (6, 33);
INSERT INTO tags_filters VALUES (1, 34);
INSERT INTO tags_filters VALUES (4, 35);
INSERT INTO tags_filters VALUES (10, 35);
INSERT INTO tags_filters VALUES (5, 36);
INSERT INTO tags_filters VALUES (2, 36);
INSERT INTO tags_filters VALUES (5, 37);
INSERT INTO tags_filters VALUES (2, 37);
INSERT INTO tags_filters VALUES (7, 38);
INSERT INTO tags_filters VALUES (7, 39);
INSERT INTO tags_filters VALUES (7, 40);
INSERT INTO tags_filters VALUES (7, 41);
INSERT INTO tags_filters VALUES (7, 42);
INSERT INTO tags_filters VALUES (7, 43);
INSERT INTO tags_filters VALUES (20, 43);
INSERT INTO tags_filters VALUES (1, 44);
INSERT INTO tags_filters VALUES (7, 45);
INSERT INTO tags_filters VALUES (1, 46);
INSERT INTO tags_filters VALUES (13, 46);
INSERT INTO tags_filters VALUES (1, 47);
INSERT INTO tags_filters VALUES (1, 48);
INSERT INTO tags_filters VALUES (13, 48);
INSERT INTO tags_filters VALUES (1, 49);
INSERT INTO tags_filters VALUES (1, 50);
INSERT INTO tags_filters VALUES (1, 51);
INSERT INTO tags_filters VALUES (1, 52);
INSERT INTO tags_filters VALUES (5, 53);
INSERT INTO tags_filters VALUES (2, 53);
INSERT INTO tags_filters VALUES (1, 54);
INSERT INTO tags_filters VALUES (1, 55);
INSERT INTO tags_filters VALUES (5, 55);
INSERT INTO tags_filters VALUES (1, 56);
INSERT INTO tags_filters VALUES (4, 57);
INSERT INTO tags_filters VALUES (11, 57);
INSERT INTO tags_filters VALUES (4, 58);
INSERT INTO tags_filters VALUES (1, 58);
INSERT INTO tags_filters VALUES (5, 58);
INSERT INTO tags_filters VALUES (10, 59);
INSERT INTO tags_filters VALUES (8, 60);
INSERT INTO tags_filters VALUES (4, 61);
INSERT INTO tags_filters VALUES (10, 61);
INSERT INTO tags_filters VALUES (4, 62);
INSERT INTO tags_filters VALUES (10, 62);
INSERT INTO tags_filters VALUES (4, 63);
INSERT INTO tags_filters VALUES (10, 63);
INSERT INTO tags_filters VALUES (11, 63);
INSERT INTO tags_filters VALUES (4, 64);
INSERT INTO tags_filters VALUES (10, 64);
INSERT INTO tags_filters VALUES (4, 65);
INSERT INTO tags_filters VALUES (5, 65);
INSERT INTO tags_filters VALUES (10, 65);
INSERT INTO tags_filters VALUES (4, 66);
INSERT INTO tags_filters VALUES (5, 66);
INSERT INTO tags_filters VALUES (10, 66);
INSERT INTO tags_filters VALUES (4, 67);
INSERT INTO tags_filters VALUES (10, 67);
INSERT INTO tags_filters VALUES (4, 68);
INSERT INTO tags_filters VALUES (10, 68);
INSERT INTO tags_filters VALUES (4, 69);
INSERT INTO tags_filters VALUES (10, 69);
INSERT INTO tags_filters VALUES (5, 70);
INSERT INTO tags_filters VALUES (10, 70);
INSERT INTO tags_filters VALUES (4, 71);
INSERT INTO tags_filters VALUES (10, 71);
INSERT INTO tags_filters VALUES (4, 72);
INSERT INTO tags_filters VALUES (10, 72);
INSERT INTO tags_filters VALUES (4, 73);
INSERT INTO tags_filters VALUES (10, 73);
INSERT INTO tags_filters VALUES (4, 74);
INSERT INTO tags_filters VALUES (5, 74);
INSERT INTO tags_filters VALUES (10, 74);
INSERT INTO tags_filters VALUES (4, 75);
INSERT INTO tags_filters VALUES (5, 75);
INSERT INTO tags_filters VALUES (10, 75);
INSERT INTO tags_filters VALUES (4, 76);
INSERT INTO tags_filters VALUES (10, 76);
INSERT INTO tags_filters VALUES (1, 77);
INSERT INTO tags_filters VALUES (1, 78);
INSERT INTO tags_filters VALUES (1, 79);
INSERT INTO tags_filters VALUES (1, 80);
INSERT INTO tags_filters VALUES (1, 81);
INSERT INTO tags_filters VALUES (1, 82);
INSERT INTO tags_filters VALUES (1, 83);
INSERT INTO tags_filters VALUES (1, 84);
INSERT INTO tags_filters VALUES (14, 85);
INSERT INTO tags_filters VALUES (1, 86);
INSERT INTO tags_filters VALUES (4, 86);
INSERT INTO tags_filters VALUES (7, 87);
INSERT INTO tags_filters VALUES (17, 87);
INSERT INTO tags_filters VALUES (7, 88);
INSERT INTO tags_filters VALUES (9, 88);
INSERT INTO tags_filters VALUES (7, 89);
INSERT INTO tags_filters VALUES (17, 89);
INSERT INTO tags_filters VALUES (7, 90);
INSERT INTO tags_filters VALUES (17, 90);
INSERT INTO tags_filters VALUES (7, 91);
INSERT INTO tags_filters VALUES (17, 91);
INSERT INTO tags_filters VALUES (7, 92);
INSERT INTO tags_filters VALUES (17, 92);
INSERT INTO tags_filters VALUES (7, 93);
INSERT INTO tags_filters VALUES (17, 93);
INSERT INTO tags_filters VALUES (7, 94);
INSERT INTO tags_filters VALUES (18, 94);
INSERT INTO tags_filters VALUES (7, 95);
INSERT INTO tags_filters VALUES (9, 95);
INSERT INTO tags_filters VALUES (21, 95);
INSERT INTO tags_filters VALUES (7, 96);
INSERT INTO tags_filters VALUES (7, 97);
INSERT INTO tags_filters VALUES (7, 98);
INSERT INTO tags_filters VALUES (7, 99);
INSERT INTO tags_filters VALUES (7, 100);
INSERT INTO tags_filters VALUES (7, 101);
INSERT INTO tags_filters VALUES (7, 102);
INSERT INTO tags_filters VALUES (7, 103);
INSERT INTO tags_filters VALUES (7, 104);
INSERT INTO tags_filters VALUES (7, 105);
INSERT INTO tags_filters VALUES (7, 106);
INSERT INTO tags_filters VALUES (7, 107);
INSERT INTO tags_filters VALUES (7, 108);
INSERT INTO tags_filters VALUES (7, 109);
INSERT INTO tags_filters VALUES (7, 110);
INSERT INTO tags_filters VALUES (7, 111);
INSERT INTO tags_filters VALUES (7, 112);
INSERT INTO tags_filters VALUES (7, 113);
INSERT INTO tags_filters VALUES (4, 113);
INSERT INTO tags_filters VALUES (22, 113);
INSERT INTO tags_filters VALUES (7, 114);
INSERT INTO tags_filters VALUES (7, 115);
INSERT INTO tags_filters VALUES (7, 116);
INSERT INTO tags_filters VALUES (7, 117);
INSERT INTO tags_filters VALUES (18, 117);
INSERT INTO tags_filters VALUES (7, 118);
INSERT INTO tags_filters VALUES (18, 118);
INSERT INTO tags_filters VALUES (7, 119);
INSERT INTO tags_filters VALUES (18, 119);
INSERT INTO tags_filters VALUES (7, 120);

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
