#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START basic-musl ####"
./busybox sh /musl/.basic_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END basic-musl ####"
exit $status
