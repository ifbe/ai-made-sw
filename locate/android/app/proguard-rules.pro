# 默认保留所有 native 方法和类
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions
-keepattributes SourceFile,LineNumberTable

# 保护 Application 类不被 R8 移除
-keep class com.example.locate.LocateApp { *; }

# 保护所有 Activity（启动页、地图页）
-keep class com.example.locate.ui.login.LoginActivity { *; }
-keep class com.example.locate.ui.map.MapActivity { *; }

# 保护前台服务
-keep class com.example.locate.service.LocationTrackerService { *; }

# 保护 Google Play 服务和 Compose 相关
-keep class com.google.android.gms.** { *; }
-keep class androidx.activity.** { *; }
-keep class androidx.compose.** { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# 保留 WebSocket listener 回调
-keep class com.example.locate.data.remote.ApiClient$ApiListener { *; }
-keep class com.example.locate.data.remote.ApiClient$ConnectionListener { *; }

# JSONObject
-keep class org.json.** { *; }
-keepclassmembers class org.json.** { *; }

# 保留数据类字段（User, Position, ServerMessage 等）
-keep class com.example.locate.domain.model.** { *; }

# Kotlin
-keep class kotlin.** { *; }
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**
-keepclassmembers class **$WhenMappings {
    <fields>;
}
