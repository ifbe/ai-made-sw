package com.example.locate.util

object Constants {
    // TODO: 部署前改成实际服务器地址
    const val DEFAULT_SERVER_URL = "https://deepstack.tech:9999"

    const val API_CHALLENGE = "/api/challenge"
    const val WS_PATH = "/"

    const val CHALLENGE_TIMEOUT_MS = 30_000L
    const val LOCATION_UPDATE_INTERVAL_MS = 5_000L
    const val LOCATION_FASTEST_INTERVAL_MS = 3_000L

    const val NOTIFICATION_CHANNEL_ID = "location_tracker"
    const val NOTIFICATION_ID = 1001

    const val PREFS_NAME = "secure_prefs"
    const val KEY_USERNAME = "username"
    const val KEY_PASSWORD = "password"
    const val KEY_TOKEN = "token"
    const val KEY_SERVER_URL = "server_url"
}
