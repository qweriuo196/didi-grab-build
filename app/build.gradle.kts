plugins {
    id("com.android.application")
}

android {
    namespace = "com.seagull.didigrab"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.seagull.didigrab"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
    // LSPosed adds this automatically at runtime
}
