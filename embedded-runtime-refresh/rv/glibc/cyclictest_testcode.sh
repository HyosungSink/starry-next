#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START cyclictest-glibc ####"
./busybox sh /glibc/.cyclictest_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END cyclictest-glibc ####"
exit $status
