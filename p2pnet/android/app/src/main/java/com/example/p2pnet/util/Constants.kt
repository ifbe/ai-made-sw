package com.example.p2pnet.util

object Constants {
    const val DEFAULT_SERVER_HOST = "deepstack.tech"
    const val DEFAULT_SERVER_PORT = 10000

    const val PREFS_NAME = "p2pnet_prefs"
    const val KEY_SERVER_HOST = "server_host"
    const val KEY_SERVER_PORT = "server_port"
    const val KEY_USERNAME = "username"
    const val KEY_LOGGED_IN = "logged_in"

    /** 是否已经提示过「忽略电池优化」（每次安装只提示一次） */
    const val KEY_BATTERY_OPT_ASKED = "battery_opt_asked"
}
