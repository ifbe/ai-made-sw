package com.example.chatroom.participants

class SerialNative {
    companion object {
        init {
            System.loadLibrary("pty")
        }
    }

    external fun openSerial(device: String, baud: Int): Int
    external fun readSerial(fd: Int, buf: ByteArray, timeoutMs: Int): Int
    external fun writeSerial(fd: Int, data: String): Int
    external fun closeSerial(fd: Int)
}
