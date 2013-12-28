/* check sha512 result against test data */
sel
i,
hash_sha512(input_data),
case
 when hash_sha512(input_data) = output_data then 'OK'
 else 'NG'
end as "result"
from
sha512_test
order by 1;
