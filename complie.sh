read type
if [ "$type" == 'curl' ]; then
arm-linux-androideabi-gcc post.c -o post.bin -lcurl -lssl -lcrypto -lz  -I"output/curl/include" -L"output/"
adb push post.bin /test
fi

if [ "$type" == 'post' ]; then
arm-linux-androideabi-gcc --static monitor.c -o monitor.bin -lpcap -I"/Users/garytan/Desktop/android-sdk-macosx/android-toolchain/bin/output/libpcap-1.7.4/" -L"/Users/garytan/Desktop/android-sdk-macosx/android-toolchain/bin/output/"
adb push monitor.bin /test
fi