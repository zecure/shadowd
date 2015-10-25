DELIMITER //

CREATE FUNCTION prepare_wildcard (input text) RETURNS text DETERMINISTIC
BEGIN
    DECLARE escape_us   text;
    DECLARE escape_pc   text;
    DECLARE wildcard1   text;
    DECLARE unescape_ar text;
    DECLARE wildcard2   text;

    SET escape_us   = REPLACE(input, '_', '\\_');
    SET escape_pc   = REPLACE(escape_us, '%', '\\%');
    SET wildcard1   = REPLACE(escape_pc, '*', '{WILDCARD}');
    SET unescape_ar = REPLACE(wildcard1, '\\{WILDCARD}', '*');
    SET wildcard2   = REPLACE(unescape_ar, '{WILDCARD}', '%');

    RETURN wildcard2;
END; //

DELIMITER ;

ALTER TABLE requests ADD resource text NOT NULL DEFAULT '';
