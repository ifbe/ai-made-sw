package com.example.chatroom.participants

class PtyNative {
    companion object {
        init {
            System.loadLibrary("pty")
        }
    }

    external fun createPty(device: String, shell: String): Int
    external fun readPty(fd: Int, buf: ByteArray, timeoutMs: Int): Int
    external fun writePty(fd: Int, data: String): Int
    external fun closePty(fd: Int)
    external fun getPid(masterFd: Int): Int
}
