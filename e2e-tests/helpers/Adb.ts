// Shared `adb` binary resolution.
//
// RebootDevice.ts invoked a
// bare `adb`, which only works when the platform-tools directory happens to be
// on PATH — every wdio config already resolved it from ANDROID_HOME instead, so
// a reboot could fail with ENOENT on a machine where the suites themselves run
// fine. One resolver, used everywhere.

/** Absolute path to `adb`, resolved from ANDROID_HOME with the macOS default. */
export function adbPath(): string {
    return process.env.ANDROID_HOME
        ? `${process.env.ANDROID_HOME}/platform-tools/adb`
        : `${process.env.HOME}/Library/Android/sdk/platform-tools/adb`
}

/**
 * `adb` args targeting one device. ALWAYS prefer this over bare args: with more
 * than one device/emulator attached, an un-targeted adb command fails with
 * "more than one device/emulator" — or, worse, acts on the wrong phone.
 */
export function adbArgs(udid: string | undefined, args: string[]): string[] {
    return udid ? ['-s', udid, ...args] : args
}
