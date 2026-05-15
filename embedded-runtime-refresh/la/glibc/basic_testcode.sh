#!/busybox sh
./busybox echo "#### OS COMP TEST GROUP START basic-glibc ####"
./busybox sh /glibc/.basic_testcode.sh.raw
status=$?
./busybox echo "#### OS COMP TEST GROUP END basic-glibc ####"
exit $status
