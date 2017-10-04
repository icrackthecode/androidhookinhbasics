#!/bin/sh

make clean
make
adb push ../libs/armeabi-v7a/target /data/local/tmp/
