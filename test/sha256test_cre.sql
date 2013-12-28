/* table to store test data */
create table sha256_test (
 i int not null,
 input_data varchar(256) character set latin not null,
 output_data char(64) character set latin Not null
) unique primary index (i);
