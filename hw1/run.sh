#!/bin/bash

echo "*** Example 1 ***"
./launcher ./sandbox.so config.txt cat /etc/passwd
echo ""
echo "*** Example 2 ***"
./launcher ./sandbox.so config.txt cat /etc/hosts
echo ""
echo "*** Example 3 ***"
./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem
echo ""
echo "*** Example 5 ***"
./launcher ./sandbox.so config.txt wget http://google.com -t 1
echo ""
echo "*** Example 6 ***"
./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1
echo ""
echo "*** Example 7 ***"
./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1
echo ""
echo "*** Example 8 ***"
./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'
echo ""