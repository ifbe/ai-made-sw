package com.example.pusher.utils

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import java.io.File

/**
 * 本地录制的落盘位置：默认就是**固定文件名** /sdcard/Download/pusher.mp4。
 *
 * 存储限制按版本分流：
 *  - API ≤ 29：直接用 File 写公共下载目录（需要 WRITE_EXTERNAL_STORAGE；
 *    API 29 还需要 application 上的 requestLegacyExternalStorage）
 *  - API ≥ 30：公共目录不再允许直接 File 写，改走 **MediaStore.Downloads**
 *    （RELATIVE_PATH=Download），**不需要任何存储权限**
 *
 * 文件名固定 ⇒ 每次录制**覆盖同名文件**（MediaStore 不会自动改名成 pusher (1).mp4）。
 * 扩展名按「封装」下拉修正：flv→.flv、fMP4→.mp4、mpegts→.ts，避免文件名和实际容器对不上。
 */
object RecordPath {

    private const val TAG = "RecordPath"

    /** 默认目录 + 默认文件名（界面上的默认值也用它们拼） */
    const val DEFAULT_DIR = "/sdcard/Download"
    const val DEFAULT_BASE = "pusher"
    /** 默认文件：扩展名跟默认封装（flv）一致；切封装时界面会自动改后缀 */
    const val DEFAULT_FILE = "$DEFAULT_DIR/$DEFAULT_BASE.flv"

    /** 公共下载目录的常见写法，统一归一化成 "download" */
    private val DOWNLOAD_ALIASES = setOf(
        "/sdcard/download",
        "/storage/emulated/0/download",
        "/storage/self/primary/download",
        "download"
    )

    fun isDownloadDir(dir: String): Boolean {
        val p = dir.trim().trimEnd('/').lowercase()
        return p.isEmpty() || DOWNLOAD_ALIASES.contains(p)
    }

    /** 这个路径最终会怎么落地（写进特殊日志，方便判断"能不能录"） */
    fun describe(typedPath: String): String {
        val p = typedPath.trim().ifBlank { DEFAULT_FILE }
        val dir = dirOf(p)
        return when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && isDownloadDir(dir) ->
                "$p → 走 MediaStore 的「下载」目录，不需要存储权限"
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                "$p → 非公共下载目录：Android 11+ 需要「所有文件访问」权限，否则会写失败"
            else ->
                "$p → 直接写文件，需要存储权限（Android 10 及以下）"
        }
    }

    /** 录制目标：要么是普通 File，要么是 MediaStore 的 content Uri */
    data class Target(val displayPath: String, val file: File?, val uri: Uri?)

    /**
     * 准备录制文件。
     *
     * @param typedPath 界面里填的路径：可以是完整文件路径（/sdcard/Download/pusher.mp4），
     *                  也可以只填目录（/sdcard/Download，这时用默认名 pusher）
     * @param ext       实际容器扩展名（flv/mp4/ts）——会覆盖用户填的扩展名，避免名实不符
     */
    fun prepare(context: Context, typedPath: String, ext: String): Target? {
        val trimmed = typedPath.trim().ifBlank { DEFAULT_FILE }
        val typedName = fileNameOf(trimmed)
        val dir = dirOf(trimmed).ifBlank { DEFAULT_DIR }
        val base = typedName.substringBeforeLast('.', missingDelimiterValue = typedName)
            .ifBlank { DEFAULT_BASE }
        val fileName = "$base.$ext"
        if (typedName.isNotEmpty() && typedName != fileName) {
            AppLog.log("录制扩展名按封装修正: $typedName → $fileName")
        }
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && isDownloadDir(dir)) {
                prepareViaMediaStore(context, fileName)
            } else {
                prepareViaFile(dir, fileName)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "prepare failed", t)
            AppLog.log("录制文件准备失败: ${t.message}")
            null
        }
    }

    /** Android 11+ 的公共下载目录：先删同名旧文件（固定文件名＝覆盖），再建新条目 */
    private fun prepareViaMediaStore(context: Context, fileName: String): Target? {
        val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val relPath = Environment.DIRECTORY_DOWNLOADS + "/"
        try {
            val selection = "${MediaStore.MediaColumns.DISPLAY_NAME}=? AND " +
                    "${MediaStore.MediaColumns.RELATIVE_PATH}=?"
            val deleted = context.contentResolver.delete(
                collection, selection, arrayOf(fileName, relPath)
            )
            if (deleted > 0) {
                AppLog.log("录制覆盖同名文件: ${Environment.DIRECTORY_DOWNLOADS}/$fileName")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "delete old entry failed", t)
        }

        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeOf(fileName))
            // 录制期间对其它应用不可见，写完由 LocalRecorder 清掉 pending
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = context.contentResolver.insert(collection, values)
        if (uri == null) {
            AppLog.log("录制文件创建失败：MediaStore 拒绝（Download/$fileName）")
            return null
        }
        return Target("$DEFAULT_DIR/$fileName", null, uri).also {
            AppLog.log("录制文件已就绪: ${it.displayPath}（MediaStore）")
        }
    }

    private fun prepareViaFile(dir: String, fileName: String): Target? {
        val d = File(dir)
        if (!d.exists() && !d.mkdirs()) {
            AppLog.log("录制目录不可用: $dir")
            return null
        }
        val f = File(d, fileName)
        return Target(f.absolutePath, f, null).also {
            AppLog.log("录制文件已就绪: ${it.displayPath}（同名会被覆盖）")
        }
    }

    /** 形如 /x/y/z.mp4（最后一段带扩展名）才算"填了文件名" */
    private fun fileNameOf(path: String): String {
        val last = path.trimEnd('/').substringAfterLast('/')
        return if (last.contains('.') && !last.startsWith('.')) last else ""
    }

    private fun dirOf(path: String): String {
        val p = path.trim().trimEnd('/')
        return if (fileNameOf(p).isNotEmpty()) p.substringBeforeLast('/') else p
    }

    private fun mimeOf(fileName: String): String = when {
        fileName.endsWith(".mp4", true) -> "video/mp4"
        fileName.endsWith(".ts", true) -> "video/mp2t"
        else -> "video/x-flv"
    }
}
