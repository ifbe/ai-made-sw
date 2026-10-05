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

    /** WireGuard 页配置（JSON 原文，解析在 ViewModel 里做，见 ui/PageConfig.kt） */
    const val KEY_WG_CONFIG = "wg_config"

    /** Switch 页配置（JSON 原文） */
    const val KEY_SWITCH_CONFIG = "switch_config"

    /** Proxy 页（端口转发）配置（JSON 原文） */
    const val KEY_PROXY_CONFIG = "proxy_config"

    /** VPN 页（一对一 tun/tap）配置（JSON 原文） */
    const val KEY_VPN_CONFIG = "vpn_config"

    /** media 页（多媒体聊天）配置（JSON 原文） */
    const val KEY_MEDIA_CONFIG = "media_config"
}
