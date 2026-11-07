/**
 * Reads the repo's single source of truth for the app version
 * (`../version.properties`, plain `key=value` text — NOT in the secrets deny
 * list) so e2e specs can synthesize "definitely higher" / "definitely lower"
 * versions without ever hardcoding a literal. Never hardcode a version here
 * or at any call site: the pre-push hook auto-increments the PATCH on every
 * push, so a hardcoded "next" version would silently go stale (or, worse,
 * collide with the real current version and stop being "higher").
 *
 *   import { currentVersion, higherThanCurrent, lowerThanCurrent } from '../helpers/AppVersion'
 */
import * as fs from 'fs'
import * as path from 'path'

// e2e-tests/helpers/AppVersion.ts -> ../.. -> repo root.
const VERSION_PROPERTIES = path.resolve(__dirname, '..', '..', 'version.properties')

interface Triple {
    major: number
    minor: number
    patch: number
}

function readVersionName(): string {
    const text = fs.readFileSync(VERSION_PROPERTIES, 'utf8')
    const m = text.match(/^versionName=(\S+)\s*$/m)
    if (!m) {
        throw new Error(`AppVersion: no "versionName=" line found in ${VERSION_PROPERTIES}`)
    }
    return m[1]
}

function parse(v: string): Triple {
    const parts = v.split('.')
    if (parts.length !== 3 || parts.some((p) => !/^\d+$/.test(p))) {
        throw new Error(`AppVersion: "${v}" is not a MAJOR.MINOR.PATCH version`)
    }
    const [major, minor, patch] = parts.map((p) => parseInt(p, 10))
    return { major, minor, patch }
}

function format(t: Triple): string {
    return `${t.major}.${t.minor}.${t.patch}`
}

/** The app's own current version, as recorded in version.properties. */
export function currentVersion(): string {
    return readVersionName()
}

/**
 * A version strictly higher than the app's current one (PATCH + 1) — always
 * derived from version.properties at call time, so it stays "higher" no
 * matter how many times the pre-push hook has bumped PATCH since this file
 * was last touched.
 */
export function higherThanCurrent(): string {
    const t = parse(readVersionName())
    return format({ ...t, patch: t.patch + 1 })
}

/**
 * A version strictly lower than any real release of this app. Only ordering
 * matters here — the mock relay's advertised value just needs to compare as
 * "not newer" against whatever the app under test happens to be — so this is
 * unconditionally `0.0.1`, never derived from the current version.
 */
export function lowerThanCurrent(): string {
    return '0.0.1'
}
