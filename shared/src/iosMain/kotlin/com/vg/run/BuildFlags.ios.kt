@file:OptIn(kotlin.experimental.ExperimentalNativeApi::class)

package com.vg.run

// kotlin.native.Platform.isDebugBinary — false for the optimized release
// XCFramework, true for the debug framework the e2e/dev builds link.
internal actual val isDebugBuild: Boolean = Platform.isDebugBinary
