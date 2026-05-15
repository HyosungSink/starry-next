#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START cyclictest-musl ####"
./busybox sh /musl/.cyclictest_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END cyclictest-musl ####"
exit $status
