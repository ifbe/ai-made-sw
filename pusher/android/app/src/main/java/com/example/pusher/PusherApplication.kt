package com.example.pusher

import android.app.Application
import android.util.Log

/**
 * 自定义 Application，最早入口，安装 CrashHandler。
 *
 * 在 AndroidManifest.xml 注册：
 *   <application android:name=".PusherApplication" ...>
 */
class PusherApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.d("PusherApplication", "onCreate, installing CrashHandler")
        CrashHandler.init(this)
    }
}
