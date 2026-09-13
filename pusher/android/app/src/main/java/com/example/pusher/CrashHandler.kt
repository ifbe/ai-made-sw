package com.example.pusher

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 全局未捕获异常处理器。
 *
 * 把崩溃现场（线程、设备、异常类型、完整栈）写入 filesDir/last_crash.txt，
 * 方便下次启动时取出，也避免 logcat 被刷掉找不到。
 */
class CrashHandler private constructor(private val appContext: Context) : Thread.UncaughtExceptionHandler {

    private val previous: Thread.UncaughtExceptionHandler? =
        Thread.getDefaultUncaughtExceptionHandler()

    private val timestampFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    fun install() {
        Thread.setDefaultUncaughtExceptionHandler(this)
        Log.i(TAG, "CrashHandler installed, previous=${previous?.javaClass?.simpleName}")
    }

    override fun uncaughtException(t: Thread, e: Throwable) {
        try {
            writeCrashLog(t, e)
        } catch (writeError: Throwable) {
            Log.e(TAG, "Failed to write crash log", writeError)
        }
        // 委托给上一个 handler（通常是 RuntimeInit$KillApplicationHandler，会终止进程）
        previous?.uncaughtException(t, e)
    }

    private fun writeCrashLog(t: Thread, e: Throwable) {
        val sw = StringWriter()
        e.printStackTrace(PrintWriter(sw))
        val stackTrace = sw.toString()

        val versionName = try {
            @Suppress("DEPRECATION")
            appContext.packageManager.getPackageInfo(appContext.packageName, 0).versionName
        } catch (e2: Exception) {
            "?"
        }

        val crashFile = File(appContext.filesDir, "last_crash.txt")
        val content = buildString {
            appendLine("=== CRASH ===")
            appendLine("Time: ${timestampFormat.format(Date())}")
            appendLine("Thread: ${t.name} (id=${t.id}, priority=${t.priority}, daemon=${t.isDaemon})")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL} (SDK ${Build.VERSION.SDK_INT})")
            appendLine("App: ${appContext.packageName} v$versionName")
            appendLine()
            appendLine("Exception: ${e.javaClass.name}: ${e.message}")
            appendLine()
            appendLine("Stack trace:")
            appendLine(stackTrace)

            // 把 cause chain 也写出来
            var cause: Throwable? = e.cause
            var depth = 1
            while (cause != null && depth < 5) {
                appendLine()
                appendLine("Caused by [$depth]: ${cause.javaClass.name}: ${cause.message}")
                val csw = StringWriter()
                cause.printStackTrace(PrintWriter(csw))
                appendLine(csw.toString())
                cause = cause.cause
                depth++
            }

            appendLine("=== END ===")
        }

        crashFile.writeText(content)
        Log.e(TAG, "Crash captured to ${crashFile.absolutePath}")
        Log.e(TAG, stackTrace)
    }

    companion object {
        private const val TAG = "CrashHandler"

        @Volatile
        private var instance: CrashHandler? = null

        fun init(context: Context) {
            if (instance == null) {
                synchronized(this) {
                    if (instance == null) {
                        instance = CrashHandler(context.applicationContext)
                    }
                }
            }
            instance?.install()
        }
    }
}
