package com.example.pusher.push

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.util.Log
import com.example.pusher.utils.AppLog
import com.example.pusher.utils.RecordPath

/**
 * 本地录制（Java 侧只负责三件事：开文件、把 fd 交给 native、收尾）。
 *
 * **真正写盘在 native**：AVIO 写回调里本来就握着完整的封包字节，直接 `write(fd)` 即可 ——
 * 不跨 JNI 拷贝、不在 Java 排队、不占额外内存；「推流数据预览」照旧只收 16 字节，互不影响。
 *
 * 文件描述符来源对上层透明：
 *  - Android 11+：MediaStore 的 Download 条目（内容 Uri）
 *  - Android 10-：普通 File
 * 两者都通过 [ParcelFileDescriptor] 转成 fd 交给 native，native 负责最终 close()。
 */
class LocalRecorder(
    private val context: Context,
    private val target: RecordPath.Target,
    private val onFinished: ((String) -> Unit)? = null
) {

    companion object {
        private const val TAG = "LocalRecorder"
    }

    /** 打开输出文件并把 fd 交给 native；返回是否成功（失败则本次不录，不影响推流） */
    fun open(): Boolean {
        return try {
            val pfd = openPfd()
            if (pfd == null) {
                AppLog.log("本地录制: 无法打开输出文件 ${target.displayPath}")
                return false
            }
            val fd = pfd.detachFd()   // 之后 fd 归 native 所有，由 native 关闭
            try {
                pfd.close()
            } catch (_: Throwable) {
            }
            JniWrapper.nativeStartRecord(fd)
            AppLog.log("本地录制: 已交给 native 落盘 fd=$fd → ${target.displayPath}")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "open failed", t)
            AppLog.log("本地录制: 打开文件失败 ${t.message}")
            false
        }
    }

    private fun openPfd(): ParcelFileDescriptor? {
        val uri = target.uri
        if (uri != null) {
            return context.contentResolver.openFileDescriptor(uri, "w")
        }
        val f = target.file ?: return null
        f.parentFile?.mkdirs()
        return ParcelFileDescriptor.open(
            f,
            ParcelFileDescriptor.MODE_WRITE_ONLY or
                    ParcelFileDescriptor.MODE_CREATE or
                    ParcelFileDescriptor.MODE_TRUNCATE
        )
    }

    /** 推流结束后收尾：报告大小、清 MediaStore 的 pending（没写出东西就删掉空文件） */
    fun finish(recordedBytes: Long) {
        if (recordedBytes <= 0) {
            cleanupEmpty()
            AppLog.log("本地录制结束: 没有写入任何数据，已删除空文件")
            return
        }
        clearPending()
        val info = String.format(
            java.util.Locale.US,
            "%s（%.1f MB）",
            target.displayPath,
            recordedBytes / 1024.0 / 1024.0
        )
        AppLog.log("本地录制已保存: $info")
        onFinished?.invoke(info)
    }

    /** 没写进任何数据：把刚建出来的文件/条目删掉，别在下载目录留空文件 */
    private fun cleanupEmpty() {
        try {
            val uri = target.uri
            if (uri != null) {
                context.contentResolver.delete(uri, null, null)
            } else {
                target.file?.delete()
            }
        } catch (t: Throwable) {
            Log.w(TAG, "cleanup empty file failed", t)
        }
    }

    /** MediaStore 写入完成后要清掉 IS_PENDING，文件才会出现在「下载」里 */
    private fun clearPending() {
        val uri = target.uri ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        try {
            val values = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            context.contentResolver.update(uri, values, null, null)
        } catch (t: Throwable) {
            Log.w(TAG, "clear IS_PENDING failed", t)
        }
    }
}
