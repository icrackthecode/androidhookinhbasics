# Android Hooking
Android Basics on Hooking

## Build target 
 cd target/jni
 ./push.sh
 
## Build hook
if you are in target/jni do cd ../../hook/jni

else cd hook/jni
 ./push_hook.sh
 
 ## Running (No need to be root)
 
 adb shell /data/local/tmp/target
 
 adb shell /data/local/tmp/inject
 
