#!/bin/sh
# Validates that the iOS build prerequisites are met.
# Run locally to catch issues before pushing to Xcode Cloud.
#
# Usage:
#   ./iosApp/ci_scripts/test_build_prerequisites.sh

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  printf "  PASS: %s\n" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf "  FAIL: %s\n" "$1"
}

echo "=== Build prerequisite checks ==="
echo ""

# 1. gradlew has execute permission in git index
echo "-- File permissions --"
mode=$(git -C "$REPO_ROOT" ls-files -s gradlew | awk '{print $1}')
if [ "$mode" = "100755" ]; then
  pass "gradlew is executable in git ($mode)"
else
  fail "gradlew is not executable in git ($mode) — run: git update-index --chmod=+x gradlew"
fi

# 2. gradlew exists and is executable on disk
if [ -x "$REPO_ROOT/gradlew" ]; then
  pass "gradlew is executable on disk"
else
  fail "gradlew is not executable on disk — run: chmod +x gradlew"
fi

# 3. Java is available
echo ""
echo "-- Java --"
if command -v java >/dev/null 2>&1; then
  java_ver=$(java -version 2>&1 | head -1)
  pass "Java found: $java_ver"
else
  fail "Java not found — install with: brew install openjdk@17"
fi

# 4. JAVA_HOME is set
if [ -n "$JAVA_HOME" ]; then
  pass "JAVA_HOME is set: $JAVA_HOME"
else
  fail "JAVA_HOME is not set — export JAVA_HOME=\$(/usr/libexec/java_home)"
fi

# 5. ci_post_clone.sh exists and is executable
echo ""
echo "-- CI scripts --"
ci_script="$REPO_ROOT/iosApp/ci_scripts/ci_post_clone.sh"
if [ -f "$ci_script" ]; then
  pass "ci_post_clone.sh exists"
else
  fail "ci_post_clone.sh is missing"
fi

if [ -x "$ci_script" ]; then
  pass "ci_post_clone.sh is executable"
else
  fail "ci_post_clone.sh is not executable — run: chmod +x iosApp/ci_scripts/ci_post_clone.sh"
fi

ci_mode=$(git -C "$REPO_ROOT" ls-files -s iosApp/ci_scripts/ci_post_clone.sh | awk '{print $1}')
if [ "$ci_mode" = "100755" ]; then
  pass "ci_post_clone.sh is executable in git ($ci_mode)"
else
  fail "ci_post_clone.sh is not executable in git ($ci_mode)"
fi

# 6. ci_post_clone.sh installs Java
if grep -qiE "openjdk|zulu|jdk17" "$ci_script" 2>/dev/null; then
  pass "ci_post_clone.sh installs JDK"
else
  fail "ci_post_clone.sh does not install JDK — Xcode Cloud needs this"
fi

# 7. Xcode build phase references gradlew
echo ""
echo "-- Xcode project --"
pbxproj="$REPO_ROOT/iosApp/iosApp.xcodeproj/project.pbxproj"
if [ -f "$pbxproj" ]; then
  if grep -q "embedAndSignAppleFrameworkForXcode" "$pbxproj"; then
    pass "Xcode project has KMP framework build phase"
  else
    fail "Xcode project missing embedAndSignAppleFrameworkForXcode build phase"
  fi
else
  fail "project.pbxproj not found"
fi

# Summary
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
