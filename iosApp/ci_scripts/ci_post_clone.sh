#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# Xcode Cloud post-clone: provision a JDK 17 for the Gradle / KMP shared-
# framework build (the iOS app links shared.xcframework, which Gradle builds).
#
# We download Azul Zulu JDK 17 directly from Azul's CDN rather than using
# `brew install openjdk@17`. On Xcode Cloud runners the Homebrew bottle fetch
# (ghcr.io / GitHub's package CDN) is unreliable and was failing the build
# with "Unable to locate a Java Runtime" / "JDK 17 not available" (the brew
# install failed, `|| true` swallowed it, and JAVA_HOME pointed at nothing).
# A pinned direct download from cdn.azul.com is reproducible and depends on
# neither Homebrew nor the GitHub package CDN. Replaces `brew install openjdk@17`.
# ---------------------------------------------------------------------------

# Pinned Zulu 17 (LTS). cdn.azul.com URLs are stable; bump deliberately.
ZULU_BUILD="zulu17.66.19-ca-jdk17.0.19"
JDK_DIR="$HOME/zulu-jdk17"
JAVA_HOME="$JDK_DIR/Contents/Home"

if [ ! -x "$JAVA_HOME/bin/java" ]; then
  case "$(uname -m)" in
    arm64|aarch64) ARCH="aarch64" ;;
    *)             ARCH="x64" ;;
  esac

  # Supply-chain: each JDK source is PINNED to a specific build AND a SHA-256
  # pinned per arch. A download that doesn't match its pinned hash is rejected
  # (never extracted) — no TOFU. Bump the version + hash together, deliberately.
  # Primary: Azul Zulu. Fallback (different host) for cdn.azul.com outages:
  # Adoptium Temurin — a PINNED release (was "latest GA", which was unpinnable).
  ZULU_URL="https://cdn.azul.com/zulu/bin/${ZULU_BUILD}-macosx_${ARCH}.tar.gz"
  ADOPT_URL="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_${ARCH}_mac_hotspot_17.0.19_10.tar.gz"
  case "$ARCH" in
    aarch64)
      ZULU_SHA256="f2bd5afaaaa4c23eb4bf2c78913c7eb7d3d228e44209ffec652fb72388a2f25c"
      ADOPT_SHA256="8fa1eff40bb637a33613b2ccb8b12c70dc3661cc22cf8e784943715769a05336" ;;
    *)
      ZULU_SHA256="6a7b8b23f2419ea1dde7eeace0d5a4cc5dbe7bbc83a8dda35dc64aa12269d041"
      ADOPT_SHA256="03632d1fbf139ab3719a9f4b47dc206251449b87557143c822336dbf8c06560f" ;;
  esac

  mkdir -p "$JDK_DIR"
  TARBALL=/tmp/jdk17.tar.gz
  # Try each (url, sha256) in order; first download whose SHA-256 matches its
  # pin wins. A hash MISMATCH is treated like a failed download (try next) and
  # is NEVER extracted, so a tampered/MITM'd artifact cannot reach the build.
  # If no source yields a verified download the build MUST fail (no fallthrough
  # to a bogus JAVA_HOME). --retry-all-errors/-connrefused retries transient
  # network failures.
  verified=""
  for pair in "$ZULU_URL|$ZULU_SHA256" "$ADOPT_URL|$ADOPT_SHA256"; do
    url="${pair%%|*}"; want="${pair##*|}"
    echo "Downloading JDK 17 (${ARCH}): ${url}"
    rm -f "$TARBALL"
    if ! curl -fSL --connect-timeout 30 --retry 5 --retry-delay 5 \
              --retry-connrefused --retry-all-errors "$url" -o "$TARBALL"; then
      echo "WARNING: download failed from ${url} — trying next source"; continue
    fi
    got="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
    if [ "$got" = "$want" ]; then
      echo "JDK SHA-256 verified (${got})"; verified="$url"; break
    fi
    echo "WARNING: SHA-256 MISMATCH from ${url} (got ${got}, want ${want}) — rejecting, trying next source"
  done
  [ -n "$verified" ] || { echo "ERROR: no JDK 17 source produced a hash-verified download"; exit 1; }

  # Both the Zulu and Temurin macOS tarballs nest the JDK under
  # "<topdir>/Contents/Home/..." — strip the top component so
  # $JDK_DIR/Contents/Home is the JDK home.
  tar -xzf "$TARBALL" -C "$JDK_DIR" --strip-components=1
  rm -f "$TARBALL"
fi

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

# Verify Java is available.
java -version 2>&1 || { echo "ERROR: JDK 17 not available"; exit 1; }

# Pre-warm Gradle and download all dependencies while JAVA_HOME is set.
# We can't run embedAndSignAppleFrameworkForXcode here because it needs
# Xcode env vars (SDK_NAME, CONFIGURATION, etc.) that only exist inside
# a build phase. Instead we compile the shared module so the build phase
# only needs to link/embed — which is fast and still finds JAVA_HOME
# via the fallback in project.yml's build script.
REPO_ROOT="$(cd "$CI_WORKSPACE/repository" 2>/dev/null && pwd || cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
echo "Pre-warming Gradle and compiling shared module..."
./gradlew :shared:compileKotlinIosArm64 --no-daemon || echo "WARNING: Pre-compile failed (build phase will retry)"
