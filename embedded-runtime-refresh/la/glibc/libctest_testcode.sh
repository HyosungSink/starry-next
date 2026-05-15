#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START libctest-glibc ####"
./busybox sh /glibc/.libctest_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END libctest-glibc ####"
exit $status
