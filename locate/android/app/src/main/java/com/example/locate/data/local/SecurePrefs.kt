package com.example.locate.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.locate.util.Constants

/**
 * 加密存储账号密码和 token
 * 基于 EncryptedSharedPreferences，密钥由 Android Keystore 管理
 */
class SecurePrefs(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        Constants.PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    var username: String?
        get() = prefs.getString(Constants.KEY_USERNAME, null)
        set(value) = prefs.edit().putString(Constants.KEY_USERNAME, value).apply()

    var password: String?
        get() = prefs.getString(Constants.KEY_PASSWORD, null)
        set(value) = prefs.edit().putString(Constants.KEY_PASSWORD, value).apply()

    var token: String?
        get() = prefs.getString(Constants.KEY_TOKEN, null)
        set(value) = prefs.edit().putString(Constants.KEY_TOKEN, value).apply()

    var serverUrl: String
        get() = prefs.getString(Constants.KEY_SERVER_URL, Constants.DEFAULT_SERVER_URL) ?: Constants.DEFAULT_SERVER_URL
        set(value) = prefs.edit().putString(Constants.KEY_SERVER_URL, value).apply()

    /**
     * 保存登录凭证
     */
    fun saveCredentials(username: String, password: String, token: String) {
        prefs.edit()
            .putString(Constants.KEY_USERNAME, username)
            .putString(Constants.KEY_PASSWORD, password)
            .putString(Constants.KEY_TOKEN, token)
            .apply()
    }

    /**
     * 清除所有凭证
     */
    fun clearCredentials() {
        prefs.edit().clear().apply()
    }

    /**
     * 是否已保存有效凭证
     */
    fun hasCredentials(): Boolean {
        return !username.isNullOrEmpty() && !password.isNullOrEmpty()
    }
}
