time dd if=/dev/urandom bs=1M count=100 2>/dev/null | ./smallclue tail -n 1000000 > /dev/null
