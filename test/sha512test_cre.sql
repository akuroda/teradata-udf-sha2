/* table to store test data */
create table sha512_test (
 i int not null,
 input_data varchar(512) character set latin not null,
 output_data char(128) character set latin Not null
) unique primary index (i);
