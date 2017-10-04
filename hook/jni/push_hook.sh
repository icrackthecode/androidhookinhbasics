#!/bin/sh

make clean
make
adb push ../libs/armeabi-v7a/inject /data/local/tmp/
