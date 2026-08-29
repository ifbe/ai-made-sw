package com.example.chatroom.ui.chat

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import java.io.File
import java.util.UUID

/**
 * 全屏图片查看器。从 chat 消息的图片气泡点进来：
 *  - 全屏黑色背景，状态栏 / 导航栏也涂黑
 *  - 单击图片任意位置（或按返回键）退出，回到聊天界面
 *
 * 通过 Intent extra 接收图片文件路径（避免 Intent 1MB 上限）。
 * Adapter 端负责先把 imageBytes 写到 cacheDir，再启动本 activity；启动后立刻删临时文件，
 * 本 activity 在 onCreate 里同步读 + decode，期间文件仍在；decode 完不再依赖文件。
 */
class FullscreenImageActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 全屏黑色：状态栏 + 导航栏也涂黑，避免出现白条
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        window.setBackgroundDrawable(null)
        // 让内容延伸到刘海 / 状态栏后面
        window.addFlags(WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS)

        val imageView = ImageView(this).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            setBackgroundColor(Color.BLACK)
            // 单击任意位置 → finish 回到聊天
            setOnClickListener { finish() }
        }
        setContentView(imageView, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ))

        // 沉浸式：隐藏状态栏 / 导航栏（best-effort，老 API 兼容）
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = (
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
            )

        val path = intent.getStringExtra(EXTRA_IMAGE_PATH)
        if (path == null) {
            finish()
            return
        }
        val bmp = try {
            BitmapFactory.decodeFile(path)
        } catch (e: Exception) {
            null
        }
        if (bmp == null) {
            finish()
            return
        }
        imageView.setImageBitmap(bmp)
    }

    companion object {
        const val EXTRA_IMAGE_PATH = "extra_image_path"

        /**
         * 启动全屏查看。
         *  @param context 任意 Context（activity / application 都行；从 ViewHolder 拿到的 wrapped context 也行）
         *  @param bytes   完整图片字节（jpg / png / webp / gif 等）。写到 cacheDir 再启动 activity，
         *                 文件读完即删。Intent 走文件路径，避开 1MB 上限。
         */
        fun launch(context: Context, bytes: ByteArray) {
            val tmpFile = File(context.cacheDir, "img_${UUID.randomUUID()}.bin")
            try {
                tmpFile.writeBytes(bytes)
            } catch (e: Exception) {
                return
            }
            val intent = Intent(context, FullscreenImageActivity::class.java).apply {
                putExtra(EXTRA_IMAGE_PATH, tmpFile.absolutePath)
                // ViewHolder 拿到的 context 不一定是 Activity，加 NEW_TASK 兜底
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        }
    }
}