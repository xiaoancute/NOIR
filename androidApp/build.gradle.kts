plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "app.noir.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.noir.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    implementation(project(":core"))
}
