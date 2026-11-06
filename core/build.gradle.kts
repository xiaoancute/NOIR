plugins {
    kotlin("multiplatform")
    id("com.android.library")
}

kotlin {
    jvm()
    androidTarget()

    sourceSets {
        val commonMain by getting
        val jvmMain by getting
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit"))
            }
        }
    }
}

android {
    namespace = "app.noir.core"
    compileSdk = 35
}
