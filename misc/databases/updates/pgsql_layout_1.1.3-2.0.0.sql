CREATE FUNCTION prepare_wildcard(input text) RETURNS text AS $$
DECLARE
    escape_us   text;
    escape_pc   text;
    wildcard    text;
    unescape_ar text;
BEGIN
    escape_us   := REPLACE(input, '_', '\_');
    escape_pc   := REPLACE(escape_us, '%', '\%');
    wildcard    := REGEXP_REPLACE(escape_pc, '([^\\])\*', '%');
    unescape_ar := REPLACE(wildcard, '\*', '*');

    RETURN unescape_ar;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE requests ADD COLUMN resource text NOT NULL DEFAULT '';
