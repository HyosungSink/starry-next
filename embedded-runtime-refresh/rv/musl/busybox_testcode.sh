#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START busybox-musl ####"
./busybox sh /musl/.busybox_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END busybox-musl ####"
exit $status
