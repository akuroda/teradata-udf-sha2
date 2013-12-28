/* script to install the UDF */

replace function hash_sha512
  (arg varchar(32000) character set latin)
  returns char(128) character set latin
  language c
  no sql
  external name 'cs:sha512:sha512.c:cs:sha512_latin:udf_sha512_latin.c:F:sha512_latin'
  parameter style td_general;
