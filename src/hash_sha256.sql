/* script to install the UDF */

replace function hash_sha256
  (arg varchar(32000) character set latin)
  returns char(64) character set latin
  language c
  no sql
  external name 'cs:sha256:sha256.c:cs:sha256_latin:udf_sha256_latin.c:F:sha256_latin'
  parameter style td_general;
