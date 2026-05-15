#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START busybox-glibc ####"
./busybox sh /glibc/.busybox_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END busybox-glibc ####"
exit $status
