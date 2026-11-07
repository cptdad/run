# Third-party notices

Rún is licensed under GPL-3.0-or-later with the additional permission in
`LICENSE-EXCEPTION` (see `LICENSE`; art under `LICENSE-ART`). It
incorporates, links against, or ships alongside the third-party components listed
below. Each component remains under its own licence. Where a licence requires its
notice to accompany redistributions, the notice is reproduced here.

How to read the "Source" column: "POM" means the licence declared in the
dependency's Maven POM as resolved by Gradle; "file" means a licence file inside the
dependency's own source or archive, read directly; "package.json" means the `license`
field of the installed npm package; "file" entries for the Tor stack name the upstream
tag the licence file was read at. Every entry was checked against one of those
(last full pass 2026-11-05); the components linked into the two Tor binaries were
read from the binaries themselves.

Licence identifiers are SPDX identifiers (https://spdx.org/licenses/). Apache-2.0,
GPL, MPL and EPL licences are cited by identifier and link only; their full texts are
at the linked locations.

---

## 1. Android / Kotlin Multiplatform dependencies (Gradle)

Pins come from `gradle/libs.versions.toml`, `shared/build.gradle.kts`,
`androidApp/build.gradle.kts` and `fuzz/build.gradle.kts`.

### 1.1 Shipped in the app

| Component | Version | SPDX | Upstream | Source |
|---|---|---|---|---|
| Tink for Android (`com.google.crypto.tink:tink-android`) | 1.23.0 | Apache-2.0 | https://github.com/tink-crypto/tink-java | POM |
| OkHttp (`com.squareup.okhttp3:okhttp`) | 5.5.0 | Apache-2.0 | https://github.com/square/okhttp | POM |
| Okio (transitive of OkHttp, resolved by Gradle) | 3.x (resolved) | Apache-2.0 | https://github.com/square/okio | POM |
| SQLCipher for Android (`net.zetetic:sqlcipher-android`) | 4.19.0 | BSD-3-Clause (Zetetic) | https://www.zetetic.net/sqlcipher/ | POM links the Zetetic licence page; BSD text read from the SQLCipher licence file in the iOS package checkout (see 2.4) |
| AndroidX SQLite (`androidx.sqlite:sqlite`) | 2.7.1 | Apache-2.0 | https://developer.android.com/jetpack/androidx/releases/sqlite | POM |
| Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`) | 1.86 | MIT (Bouncy Castle Licence) | https://www.bouncycastle.org/ | POM; text from `META-INF/LICENSE.md` inside the jar |
| Guardian Project `tor-android` (`info.guardianproject:tor-android`) | 0.4.9.14 | BSD-3-Clause (wrapper; bundles Tor, see 1.3) | https://github.com/guardianproject/tor-android | POM |
| kotlinx.coroutines (`kotlinx-coroutines-core`) | 1.11.0 | Apache-2.0 | https://github.com/Kotlin/kotlinx.coroutines | POM |
| Kotlin standard library | 2.4.20 | Apache-2.0 | https://github.com/JetBrains/kotlin | POM |
| UnifiedPush connector (`org.unifiedpush.android:connector`) | 3.3.5 | Apache-2.0 | https://codeberg.org/UnifiedPush/android-connector | POM |
| ZXing core (`com.google.zxing:core`) | 3.5.4 | Apache-2.0 | https://github.com/zxing/zxing | POM (parent `zxing-parent`) |
| AndroidX Core KTX | 1.19.0 | Apache-2.0 | https://developer.android.com/jetpack/androidx | POM |
| AndroidX Lifecycle (runtime-ktx, viewmodel-compose, runtime-compose) | 2.11.0 | Apache-2.0 | https://developer.android.com/jetpack/androidx | POM (runtime-ktx version from catalog; others pinned inline; POM read for related Jetpack artifacts) |
| AndroidX Activity Compose | 1.13.0 | Apache-2.0 | https://developer.android.com/jetpack/androidx | POM (same AndroidX licence terms) |
| AndroidX Navigation Compose | 2.10.1 | Apache-2.0 | https://developer.android.com/jetpack/androidx | POM |
| AndroidX CameraX (camera2, lifecycle, view) | 1.6.2 | Apache-2.0 | https://developer.android.com/jetpack/androidx/releases/camera | POM (camera-camera2) |
| AndroidX Fragment / AppCompat (constraint pins) | 1.9.0 / 1.8.0 | Apache-2.0 | https://developer.android.com/jetpack/androidx | POM (`fragment-1.9.0.pom`, `appcompat-1.8.0.pom`) |
| Jetpack Compose BOM, UI, Graphics, Material 3 | BOM 2026.09.00 (material3 resolves 1.4.0) | Apache-2.0 | https://developer.android.com/jetpack/compose | POM (material3) |

Notes for 1.1:

- No NOTICE file ships in the Apache-2.0 artifacts above that we inspected (Tink,
  OkHttp, UnifiedPush connector, ZXing); none is required to be reproduced. The
  Apache-2.0 text is at https://www.apache.org/licenses/LICENSE-2.0.
- Okio's exact resolved version was not pinned by us; the Gradle cache holds 3.12.0
  and 3.18.1.

#### Bouncy Castle (reproduced as the licence requires)

```
MIT License (https://opensource.org/licenses/MIT)

Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sub license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

#### SQLCipher (Zetetic BSD notice; reproduced as the licence requires)

```
Copyright (c) 2008-2023, ZETETIC LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the ZETETIC LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

The SQLCipher core is built on SQLite, which is in the public domain
(https://sqlite.org/copyright.html).

### 1.2 Test-only and fuzz-only (not shipped in the app)

| Component | Version | SPDX | Source |
|---|---|---|---|
| JUnit 4 | 4.13.2 | EPL-1.0 | POM |
| AndroidX Test JUnit extension | 1.3.0 | Apache-2.0 | POM (`junit-1.3.0.pom`) |
| AndroidX Espresso core | 3.7.0 | Apache-2.0 | POM (`espresso-core-3.7.0.pom`) |
| Compose UI test (junit4, manifest), UI tooling | via BOM (resolve to 1.12.1) | Apache-2.0 | POM (`ui-test-junit4-1.12.1.pom`, `ui-test-manifest-1.12.1.pom`, `ui-tooling-1.12.1.pom`) |
| OkHttp MockWebServer | 5.5.0 | Apache-2.0 | POM |
| kotlinx-coroutines-test | 1.11.0 | Apache-2.0 | same project as coroutines-core (POM) |
| Jazzer JUnit (`com.code-intelligence:jazzer-junit`, `:fuzz` module) | 0.30.0 | Apache-2.0 | POM (https://github.com/CodeIntelligenceTesting/jazzer) |
| JUnit Jupiter API / Params / Engine (`:fuzz`) | 5.14.4 | EPL-2.0 | POM (api) |
| JUnit Platform Launcher (`:fuzz`) | 1.14.4 | EPL-2.0 | POM (`junit-platform-launcher-1.14.4.pom`); upstream `LICENSE.md` at tag `r5.14.4` is EPL-2.0 |

### 1.3 Tor inside `tor-android` (Android)

`tor-android` 0.4.9.14 ships `libtor.so` for arm64-v8a, armeabi-v7a, x86 and x86_64
(read from the AAR). The library packages the Tor daemon together with its native
dependencies.

The `tor-android` POM declares "The 3-Clause BSD License". The components statically
linked into `libtor.so` were read from the arm64-v8a binary itself (version strings
and exported symbols, 2026-11-05); the only shared-library dependencies are Android's
`libc`, `libdl`, `liblog` and `libm`. No liblzma is linked in this build.

| Component | Version | SPDX | Upstream | Source |
|---|---|---|---|---|
| Tor | 0.4.9.14 | BSD-3-Clause | https://www.torproject.org/ | version string in `libtor.so`; `LICENSE` at tag `tor-0.4.9.14` (file) |
| OpenSSL | 3.5.9 | Apache-2.0 | https://www.openssl.org/ | `OpenSSL 3.5.9 29 Sep 2026` in `libtor.so`; `LICENSE.txt` at tag `openssl-3.5.9` (file) |
| libevent | 2.1.13-stable | BSD-3-Clause | https://libevent.org/ | version string in `libtor.so`; `LICENSE` at tag `release-2.1.13-stable` (file) |
| zlib | 1.3.2 | Zlib | https://zlib.net/ | `inflate 1.3.2` / `deflate 1.3.2` in `libtor.so`; `LICENSE` at tag `v1.3.2` (file) |
| Zstandard (libzstd) | 1.5.7 | BSD-3-Clause (upstream also offers GPL-2.0; we use it under BSD) | https://github.com/facebook/zstd | 292 exported `ZSTD_*` symbols + `1.5.7` in `libtor.so`; `LICENSE` at tag `v1.5.7` (file) |

Tor copyright line: Copyright (c) 2001-2004, Roger Dingledine; (c) 2004-2007, Roger
Dingledine and Nick Mathewson; (c) 2007-, The Tor Project, Inc. Tor is distributed
under the 3-clause BSD licence (https://gitlab.torproject.org/tpo/core/tor/-/blob/tor-0.4.9.14/LICENSE,
read 2026-11-05). The same file places `src/ext/strlcat.c`, `src/ext/strlcpy.c` and
`src/ext/tor_queue.h` under their own BSD-style licences; see that file.

#### 3-clause BSD notices (Tor, libevent, Zstandard; reproduced as the licence requires)

The following holders' code is distributed under the 3-clause BSD licence, whose
conditions and disclaimer are reproduced once in section 1.1 (SQLCipher) and apply
here with the respective holder's name in place of ZETETIC LLC:

- Tor: Copyright (c) 2001-2004, Roger Dingledine; Copyright (c) 2004-2007, Roger
  Dingledine, Nick Mathewson; Copyright (c) 2007-, The Tor Project, Inc.
- libevent: Copyright (c) 2000-2007 Niels Provos; Copyright (c) 2007-2012 Niels Provos
  and Nick Mathewson.
- Zstandard: Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

zlib notice: (C) 1995-2026 Jean-loup Gailly and Mark Adler; provided 'as-is' under the
zlib licence (https://zlib.net/zlib_license.html).

### 1.4 Native Argon2 on Android

`librunargon2.so` is built from the same vendored Argon2 sources as iOS (section 2.3),
via `shared/src/androidMain/cpp/CMakeLists.txt`.

---

## 2. Vendored and linked iOS components

### 2.1 Tor runtime: `iosApp/Frameworks/tor.xcframework`

Built from source via `iosApp/scripts/build-tor-xcframework.sh` from the iCepa project
(https://github.com/iCepa/Tor.framework), tag `v409.14.1`, with Tor pinned to
0.4.9.14. The components statically linked into the shipped `ios-arm64` binary were
read from the binary itself (version strings and symbols, 2026-11-05); zlib is NOT
bundled on iOS — the binary links the system `/usr/lib/libz.1.dylib` — and no
Zstandard is linked.

| Component | Version | SPDX | Upstream | Source |
|---|---|---|---|---|
| Tor | 0.4.9.14 | BSD-3-Clause | https://www.torproject.org/ | `tor 0.4.9.14` in the binary; `LICENSE` at tag `tor-0.4.9.14` (file) |
| OpenSSL | 3.6.5 | Apache-2.0 | https://www.openssl.org/ | `OpenSSL 3.6.5 29 Sep 2026` in the binary; `LICENSE.txt` at tag `openssl-3.6.5` (file) |
| libevent | 2.1.13-stable | BSD-3-Clause | https://libevent.org/ | version string in the binary; `LICENSE` at tag `release-2.1.13-stable` (file) |
| xz (liblzma) | 5.8.4 | 0BSD | https://tukaani.org/xz/ | `5.8.4` + 142 `_lzma_*` symbols in the binary; `COPYING` at tag `v5.8.4` (file: "liblzma is under the BSD Zero Clause License (0BSD)") |

Versions match the pins in `iosApp/scripts/build-tor-xcframework.sh` (`ICEPA_TAG`,
`TOR_VERSION`). Tor's and libevent's copyright lines are given in 1.3 and apply here
too. The OpenSSL 3.x series is Apache-2.0 (https://www.openssl.org/source/license.html).

### 2.2 iCepa Objective-C wrapper: `iosApp/Tor/`

Vendored from iCepa `Tor.framework` (https://github.com/iCepa/Tor.framework), the
`Tor/Classes/Core` and `CTor` sources. SPDX: MIT — the upstream `LICENSE` file at the
pinned tag `v409.14.1` (read 2026-11-05) is the MIT licence, "Copyright (c) 2015-2026
The iCepa Contributors: Conrad Kramer, Chris Ballinger, Mike Tigas, Benjamin Erhart".
The vendored file headers themselves carry no licence text. MIT notice (reproduced as
the licence requires):

```
Copyright (c) 2015-2026 The iCepa Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions: The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

Copyright lines found in the file headers (only authorship lines; no year-range
copyright statement exists in them):

| File(s) | Header line |
|---|---|
| `TORThread.m`, `TORController.m` (and the other classes of the original Core set) | `Created by Conrad Kramer on 7/19/15` (TORThread), `on 5/10/14` (TORController) |
| `NSBundle+GeoIP.h/.m` | `Created by Benjamin Erhart on 02.12.21` |
| `TORLogging.h/.m` | `Created by Benjamin Erhart on 9/9/17` |

Local modification: `TORThread.m` has a one-element bounds fix (`argv[argc + 1]`), and
the unused onion-auth classes were removed (`iosApp/SwiftTor-VERIFICATION.md`).

### 2.3 Argon2 reference implementation: `iosApp/Argon2/`

- Upstream: https://github.com/P-H-C/phc-winner-argon2, commit
  `f57e61e19229e23c4445b85494dbf7c07de721cb`
- SPDX: `CC0-1.0 OR Apache-2.0` (our choice below)
- Source: `iosApp/Argon2/LICENSE` and `iosApp/Argon2/README-VENDOR.md`, read directly.

Copyright notice carried by the upstream licence file:

```
Argon2 reference source code package - reference C implementations

Copyright 2015
Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves

You may use this work under the terms of a Creative Commons CC0 1.0
License/Waiver or the Apache Public License 2.0, at your option.
```

Rún uses this code under the Apache-2.0 option. One local modification: `blake2/blake2.h`
renames the exported blake2b symbols with an `argon2_` prefix (see README-VENDOR.md).
The unmodified licence text lives in `iosApp/Argon2/LICENSE`.

### 2.4 SQLCipher on iOS: Swift Package `swift-sqlcipher`

Linked as a Swift Package, not vendored:

- Package: https://github.com/skiptools/swift-sqlcipher.git, exact version **1.13.0**
  (revision `882c3d63a2677ccada1e841e7f15ecc6222a6b79`), pinned in
  `iosApp/iosApp.xcodeproj/project.pbxproj` (`XCRemoteSwiftPackageReference`) and the
  workspace `Package.resolved`. (`iosApp/project.yml` carries an older `from: "1.8.0"`
  constraint; the Xcode project's exact pin is authoritative.)
- Source: the package's licence files, read in a local SwiftPM checkout:

| Part | SPDX | Source |
|---|---|---|
| Package wrapper (Skip.tools, Stephen Celis) | MIT | `LICENSE.txt` |
| SQLCipher core | BSD-3-Clause (Zetetic) | `LICENSE-SQLCIPHER.txt` (text reproduced in 1.1) |
| SQLite | Public domain | `LICENSE-SQLITE.txt` |
| libtomcrypt (bundled crypto provider) | Unlicense | `SPDX-License-Identifier: Unlicense` headers in the bundled sources |

Package wrapper licence (MIT; reproduced as the licence requires):

```
(The MIT License)

Copyright (c) 2023-2025 Skip.tools (<support@skip.tools>)
Copyright (c) 2014-2015 Stephen Celis (<stephen@stephencelis.com>)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

libtomcrypt (https://github.com/libtom/libtomcrypt, by Tom St Denis) is bundled inside
`swift-sqlcipher`; it is not a separate dependency of this repository.

### 2.5 Other iOS libraries

The iOS app has no other third-party Swift Package or CocoaPods dependency: the only
`XCRemoteSwiftPackageReference` in the Xcode project is `swift-sqlcipher`. System
frameworks (CryptoKit, Network, StoreKit and so on) are Apple SDKs, see section 5.

---

## 3. Fonts

| Font | Version | SPDX | Upstream | Source |
|---|---|---|---|---|
| Metamorphous Regular (`assets/fonts/Metamorphous-Regular.ttf`) | as shipped in the file | OFL-1.1 | https://fonts.google.com/specimen/Metamorphous | `assets/fonts/OFL.txt`, read directly |

```
Copyright (c) 2011-2012 by Sorkin Type Co (www.sorkintype.com),
with Reserved Font Name "Metamorphous".
```

This Font Software is licensed under the SIL Open Font License, Version 1.1
(https://openfontlicense.org). The full licence is in `assets/fonts/OFL.txt` and must
accompany any redistribution of the font. "Metamorphous" is a Reserved Font Name: a
Modified Version of the font may not use that name.

---

## 4. Tooling shipped in the repository

None of this is part of the distributed apps; no notices are required to be
reproduced. Licences are the `license` field of the installed npm packages in
`e2e-tests/node_modules` (package.json), at the installed versions.

| Tool | Installed version | SPDX |
|---|---|---|
| webdriverio | 9.31.9 | MIT |
| @wdio/cli, @wdio/local-runner, @wdio/mocha-framework, @wdio/appium-service | 9.31.9 | MIT |
| @wdio/spec-reporter, @wdio/types | 9.31.2 | MIT |
| appium | 3.7.0 | Apache-2.0 |
| appium-uiautomator2-driver | 8.7.0 | Apache-2.0 |
| appium-xcuitest-driver | 12.12.4 | Apache-2.0 |
| typescript | 7.0.2 | Apache-2.0 |
| @types/mocha | 10.0.10 | MIT |
| @types/node | 22.20.3 | MIT |
| ios-deploy (dependency; used only as a developer tool) | 1.12.2 | GPL-3.0 (declared as `GPLv3`) |
| @vg/fleet (local sibling package, `file:../../fleet`) | local | the author's own tooling, outside this repository |

Mocha 10.8.2 is pulled in through `@wdio/mocha-framework`: MIT per its `package.json`
and its `LICENSE` file ("Copyright (c) 2011-2024 OpenJS Foundation and contributors").

Gradle wrapper: Gradle 9.7.1 (`gradle/wrapper/gradle-wrapper.properties`), SPDX
Apache-2.0, https://gradle.org. Source: the `NOTICE` and `LICENSE` files in the
extracted distribution (Apache-2.0 header read). The wrapper downloads the
distribution at build time; it is not redistributed in the apps.

---

## 5. Proprietary components

These are optional, closed-source platform SDKs provided under their vendors' own
terms. They are not covered by this repository's licence, and their source is not part
of it. The app runs without them: on devices without Google Play services, notifications
use the UnifiedPush path; without Play Billing or Apple StoreKit there is no tip jar. They
are linked into every build regardless; `LICENSE-EXCEPTION` grants the GPL section 7
permission to convey the program combined with them and through the stores.

| Component | Version | Vendor terms |
|---|---|---|
| Firebase Cloud Messaging (`com.google.firebase:firebase-messaging`), via Firebase BoM 34.19.0 | 25.1.3 (resolved from the BoM) | Firebase terms; the POM declares Apache-2.0 for the client artifact, while the service and the binary distribution are under Google's terms |
| Google Play services base (`com.google.android.gms:play-services-base`) | 18.9.0 (resolved) | Android Software Development Kit License (POM) |
| Google Play Billing (`com.android.billingclient:billing-ktx`) | 9.1.0 | Android Software Development Kit License (POM) |
| Google Play In-App Review (`com.google.android.play:review-ktx`) | 2.0.2 | Play Core Software Development Kit Terms of Service (POM) |
| Apple SDKs (iOS SDK, CryptoKit, Network, StoreKit 2, UserNotifications, Xcode toolchain) | per Xcode | Apple Developer Program License Agreement and Xcode/SDK licence |

Firebase `google-services` Gradle plugin 4.5.0 is a build-time tool under Google's
terms; it is not shipped in the app.
