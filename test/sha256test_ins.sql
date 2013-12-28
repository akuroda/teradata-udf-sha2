/* populate test data */
.import vartext ',' file=sha256test.dat
.repeat *
using (i varchar(3), c1 varchar(130), c2 varchar (64))
insert into sha256_test
 values(cast(:i as int), case when :c1 is not null then :c1 else '' end, :c2);
