time dd if=/dev/urandom bs=1M count=100 2>/dev/null | base64 | ./smallclue tr a-z A-Z > /dev/null
