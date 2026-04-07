package com.example.p2pnet.data.local

import android.content.Context
import android.content.SharedPreferences
import com.example.p2pnet.util.Constants

class LocalPrefs(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        Constants.PREFS_NAME, Context.MODE_PRIVATE
    )

    var serverHost: String
        get() = prefs.getString(Constants.KEY_SERVER_HOST, Constants.DEFAULT_SERVER_HOST) ?: Constants.DEFAULT_SERVER_HOST
        set(value) = prefs.edit().putString(Constants.KEY_SERVER_HOST, value).apply()

    var serverPort: Int
        get() = prefs.getInt(Constants.KEY_SERVER_PORT, Constants.DEFAULT_SERVER_PORT)
        set(value) = prefs.edit().putInt(Constants.KEY_SERVER_PORT, value).apply()

    var username: String?
        get() = prefs.getString(Constants.KEY_USERNAME, null)
        set(value) = prefs.edit().putString(Constants.KEY_USERNAME, value).apply()

    var loggedIn: Boolean
        get() = prefs.getBoolean(Constants.KEY_LOGGED_IN, false)
        set(value) = prefs.edit().putBoolean(Constants.KEY_LOGGED_IN, value).apply()

    fun clearSession() {
        prefs.edit()
            .remove(Constants.KEY_USERNAME)
            .putBoolean(Constants.KEY_LOGGED_IN, false)
            .apply()
    }
}
