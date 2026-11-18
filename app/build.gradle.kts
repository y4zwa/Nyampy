import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "dev.yazwa.nyampy"
    compileSdk = libs.versions.compileSdk.get().toInt()

    // The build's own number: every invocation that assembles a release APK takes the
    // next one (debug-only and test runs hold it, so a delivery's debug build carries the
    // release's number). The number rides along as versionCode, so every build installs
    // over the one before it. The file at the root carries it: visible in git, safe
    // across cleanups.
    val buildNumberFile = rootProject.file("build_number.properties")
    val releaseAssembled = gradle.startParameter.taskNames.any { name ->
        val task = name.substringAfterLast(':')
        (task.startsWith("assemble", true) || task.startsWith("bundle", true)) &&
            task.contains("Release", true)
    }
    val buildNumber = (buildNumberFile.takeIf { it.isFile }?.readText()?.trim()?.toIntOrNull() ?: 0) +
        if (releaseAssembled) 1 else 0
    if (releaseAssembled) buildNumberFile.writeText(buildNumber.toString())

    // The version's own three numbers, handed out by hand: the global release — a new
    // feature's mark, 0 while the app's whole functionality is still landing — and the
    // minor release, raised on request. The third number is the build itself: the
    // ever-counting one above, starting at 76.
    val majorVersion = 1
    val minorVersion = 0

    defaultConfig {
        applicationId = "dev.yazwa.nyampy"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = buildNumber
        // Nyampy counts its own builds: the counter stays monotonic as versionCode, while
        // the name a release carries starts at 1.0.0 for the fork's first build.
        versionName = "$majorVersion.$minorVersion.${(buildNumber - 1).coerceAtLeast(0)}"
        // The About page's build stamp: when this build was assembled, on the Moscow
        // clock with its offset said out loud. ROOT locale keeps it English, the app's
        // only language.
        val buildDate = ZonedDateTime.now(ZoneId.of("Europe/Moscow"))
            .format(DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm", Locale.ROOT)) +
            " MSK (UTC+3)"
        buildConfigField("String", "BUILD_DATE", "\"$buildDate\"")
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // The app's own release key: root chumpy.keystore + keystore.properties (both gitignored),
    // one key for both build types — a release still installs right over a debug install and
    // keeps its data, but the signature is a real identity now, not the machine's debug
    // certificate that Play Protect flags. A checkout without the pair falls back to the
    // debug key, the old way.
    val keystoreProps = rootProject.file("keystore.properties")
    if (keystoreProps.isFile) {
        val props = Properties().apply { keystoreProps.inputStream().use { load(it) } }
        signingConfigs.create("release") {
            storeFile = rootProject.file(props.getProperty("storeFile"))
            storePassword = props.getProperty("storePassword")
            keyAlias = props.getProperty("keyAlias")
            keyPassword = props.getProperty("keyPassword")
            // minSdk 26: v2 is what every device reads; v3 carries the same key for the
            // newer verifiers. v1 (JAR signing) serves nothing below 24.
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
        debug {
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        aidl = true
        buildConfig = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        // The unit tests run against the JVM's android.jar stubs; the app's own Log lines
        // (and any other framework call the tests brush past) answer with defaults rather
        // than "not mocked" throws.
        unitTests.isReturnDefaultValues = true
    }

    // The gomobile runtime is loaded from the APK the classic way, like every Xray client.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    androidResources {
        // English is the default; ru is the one translation. Per-app language
        // selection lives in the system settings (locales_config.xml).
        localeFilters += listOf("en", "ru")
    }
}

kotlin {
    compilerOptions {
        optIn.addAll(
            "androidx.compose.material3.ExperimentalMaterial3Api",
            "androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
        )
    }
}

// The mihomo core is a build artefact, not source. The tag is immutable for a given
// core build and the digest is pinned in the commit: a checkout made while an AAR is
// being replaced cannot silently keep the wrong bytes, and an old commit keeps fetching
// the AAR it was built against. A checkout without network can drop the AAR into
// app/libs by hand; the digest still decides whether it may be used.
val coreAarSha256 = "7dbb31b5d42f9e876e1e93cd240f20a7cb6a7b4f59616afb23d1c9f14b5ccefb"
val coreAarUrl = "https://github.com/y4zwa/Nyampy/releases/download/core-1.19.34-3/nyampycore.aar"
val coreAar = layout.projectDirectory.file("libs/nyampycore.aar")

fun coreAarDigest(file: java.io.File): String? {
    if (!file.exists()) return null
    val bytes = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
    return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

val fetchCoreAar = tasks.register("fetchCoreAar") {
    description = "Downloads the pinned mihomo core AAR when the local copy is missing or stale."
    outputs.file(coreAar)
    outputs.upToDateWhen { coreAarDigest(coreAar.asFile) == coreAarSha256 }
    doLast {
        val file = coreAar.asFile
        if (coreAarDigest(file) == coreAarSha256) {
            logger.lifecycle("core AAR is present and matches its sha256")
            return@doLast
        }
        file.parentFile.mkdirs()
        file.delete()
        val url = URI.create(coreAarUrl)
        logger.lifecycle("Downloading $url")
        val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()
        val response = client.send(
            HttpRequest.newBuilder(url).build(),
            HttpResponse.BodyHandlers.ofFile(file.toPath()),
        )
        check(response.statusCode() == 200) { "core AAR: HTTP ${response.statusCode()}" }
        val actual = coreAarDigest(file)
        check(actual == coreAarSha256) {
            file.delete()
            "core AAR sha256 mismatch: expected $coreAarSha256, got $actual"
        }
    }
}
tasks.named("preBuild") { dependsOn(fetchCoreAar) }

dependencies {
    // The mihomo core: a gomobile AAR built from MetaCubeX/mihomo by nyampy-core/
    // (see that project's README). Its consumer rules keep the go.Seq / nyampycore
    // bindings alive through minification.
    implementation(files("libs/nyampycore.aar"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.exifinterface)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)
    implementation(libs.work.runtime.ktx)

    // The QR scanner's decoder (com.google.zxing:core is the pure-Java part, no camera).
    implementation(libs.zxing.core)
    // The subscription logos' SVG renderer; PNG decodes natively.
    implementation(libs.androidsvg)
    // The QR scanner's camera: CameraX feeds the frames, zxing (above) decodes them.
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)

    implementation(libs.compose.ui)
    implementation(libs.compose.foundation)
    implementation(libs.compose.animation)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.material3)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
}
