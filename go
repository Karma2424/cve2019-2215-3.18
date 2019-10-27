x=su98
make $x && cp $x app/src/main/assets && adb push $x /data/local/tmp && adb shell chmod 755 /data/local/tmp/$x #&& adb shell /data/local/tmp/$x$1 