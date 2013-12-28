/* check sha256 result against test data */
sel
i,
hash_sha256(input_data),
case
 when hash_sha256(input_data) = output_data then 'OK'
 else 'NG'
end as "result"
from
sha256_test
order by 1;
