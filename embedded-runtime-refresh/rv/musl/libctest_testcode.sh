#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START libctest-musl ####"
./busybox sh /musl/.libctest_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END libctest-musl ####"
exit $status
