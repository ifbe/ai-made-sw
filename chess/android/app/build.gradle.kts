plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.chess"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.example.chess"
        minSdk = 28
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    // WebSocket 客户端 + 服务端都用这个库（纯 Java，不用引 coroutines）
    implementation(libs.java.websocket)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}