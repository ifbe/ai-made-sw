package com.example.locate

import android.app.Application
import org.osmdroid.config.Configuration

/**
 * Application 类
 */
class LocateApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // 初始化 OSMDroid 配置
        Configuration.getInstance().apply {
            userAgentValue = packageName
            // 可配置缓存等
        }
    }
}
