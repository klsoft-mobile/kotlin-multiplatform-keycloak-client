import com.android.build.api.dsl.androidLibrary
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "io.github.klsoft-mobile.kotlin.multiplatform"
version = "1.0.2"

kotlin {
    jvm()
    androidLibrary {
        namespace = "klsoft.kotlin.multiplatform"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withJava() // enable java compilation support
        withHostTestBuilder {}.configure {}
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }

        compilations.configureEach {
            compilerOptions.configure {
                jvmTarget.set(
                    JvmTarget.JVM_11
                )
            }
        }
    }
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            implementation(libs.ktor.client.core)
            implementation(libs.kotlinx.serialization.json)
        }
        jvmMain.dependencies {
            implementation(libs.ktor.client.java)
        }
        androidMain.dependencies {
            implementation(libs.ktor.client.okhttp)
        }
        iosMain.dependencies {
            implementation(libs.ktor.client.darwin)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "keycloak-client", version.toString())

    pom {
        name = "Keycloak client"
        description = "A Kotlin Multiplatform library that can be used to secure applications with Keycloak."
        inceptionYear = "2026"
        url = "https://github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client"
        licenses {
            license {
                name = "MIT"
                url = "https://github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client?tab=MIT-1-ov-file#readme"
                distribution =
                    "https://github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client?tab=MIT-1-ov-file#readme"
            }
        }
        developers {
            developer {
                id = "klsoft"
                name = "klsoft"
                url = "https://github.com/klsoft-mobile"
            }
        }
        scm {
            url = "https://github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client"
            connection = "scm:git:git://github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client.git"
            developerConnection = "scm:git:ssh://git@github.com/klsoft-mobile/kotlin-multiplatform-keycloak-client.git"
        }
    }
}
