# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# ============ JNI 回调保留规则（重要） ============
# native 侧是用字符串查找这些类/方法的：
#   GetMethodID(clazz, "onSendData", "([BJ)V")
#   GetMethodID(clazz, "onRecvData", "([BJ)V")
#   GetMethodID(clazz, "onRtmpError", "(Ljava/lang/String;)V")
# 一旦开启 minify（R8），名称会被混淆、方法可能被裁剪，查找结果变成 null，
# RTMP 的发送/接收/错误回调会静默失效（表现为日志面板没数据、错误不上报）。
-keep class com.example.pusher.push.JniWrapper { *; }
-keep interface com.example.pusher.push.AvioDataListener { *; }
-keep class * implements com.example.pusher.push.AvioDataListener { *; }
-keepclassmembers class * implements com.example.pusher.push.AvioDataListener {
    public void onSendData(byte[], long);
    public void onRecvData(byte[], long);
    public void onRtmpError(java.lang.String);
}