buildscript {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
    dependencies {
        classpath("com.gradleup.shadow:shadow-gradle-plugin:9.3.0")
    }
}
// `apply plugin` stuff are used with `buildscript`.
apply(plugin = "java")
apply(plugin = "com.gradleup.shadow")

repositories {
    mavenCentral()
}

plugins {
    id("application")
    kotlin("jvm") version "2.2.0"
    kotlin("plugin.serialization") version "2.3.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

dependencies {
    testImplementation(kotlin("test"))
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation ("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("io.github.isotes:tun-io:1.0.0")
    implementation("io.javalin:javalin:6.7.0")
    implementation("org.slf4j:slf4j-nop:2.0.16")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(20)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(20))
    }
}

application {
    mainClass = "net.rec0de.android.watchwitch.MainKt"
}