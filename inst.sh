killall lispd
cd ./module
make
rmmod lisp
insmod lisp.ko
ifconfig rloc0 up
ifconfig rloc0 203.178.143.97
ifconfig rloc0 add 2001:200:0:8801:203:178:143:97
cd ../lispd
make
./lispd -dc /home/eden/lisp/lisp.conf.sav
