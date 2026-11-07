# librunargon2.so — the vault KDF_VERSION_3 Argon2id, natively, on Android.
#
# Builds the SAME vendored PHC reference sources iOS links (iosApp/Argon2/, pinned
# by scripts/verify-argon2-src.sh) — referenced IN PLACE, never copied, so there is
# exactly one copy of the crypto core with two consumers. Only argon2_jni.c
# is Android-specific. See iosApp/Argon2/README-VENDOR.md and
# docs/vault-relay-internals.md ("Android runs Argon2id natively").
cmake_minimum_required(VERSION 3.22)
project(runargon2 LANGUAGES C)

set(ARGON2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../iosApp/Argon2")
get_filename_component(ARGON2_DIR "${ARGON2_DIR}" ABSOLUTE)
if(NOT EXISTS "${ARGON2_DIR}/argon2.h")
  message(FATAL_ERROR "vendored Argon2 sources not found at ${ARGON2_DIR}")
endif()

add_library(runargon2 SHARED
  argon2_jni.c
  "${ARGON2_DIR}/argon2.c"
  "${ARGON2_DIR}/core.c"
  "${ARGON2_DIR}/ref.c"
  "${ARGON2_DIR}/encoding.c"
  "${ARGON2_DIR}/thread.c"
  "${ARGON2_DIR}/blake2/blake2b.c"
)

target_include_directories(runargon2 PRIVATE "${ARGON2_DIR}" "${ARGON2_DIR}/blake2")

# ARGON2_NO_THREADS: supported by the vendored core.c/thread.c (fill_memory_blocks
# takes the single-thread path; thread.c compiles to an empty unit). The vault uses
# p=1, and lanes are computed sequentially with an identical result for p>1, so the
# output is unchanged — it only removes pthread use from the KDF.
# A2_VISCTL is deliberately NOT defined, so ARGON2_PUBLIC expands to nothing and
# -fvisibility=hidden keeps every argon2_* / blake2b symbol out of the dynamic
# symbol table: the only export is the JNIEXPORT entry point.
target_compile_definitions(runargon2 PRIVATE ARGON2_NO_THREADS)

# -O3 is set as a TARGET option so it lands AFTER CMAKE_C_FLAGS_<CONFIG> on the
# command line: AGP builds the debug variant with CMAKE_BUILD_TYPE=Debug (-O0), and
# the last -O wins — the debug APK runs the KDF at full speed too.
target_compile_options(runargon2 PRIVATE
  -O3
  -fvisibility=hidden
  -ffunction-sections
  -fdata-sections
  -fstack-protector-strong
  -Wall
)

# 16 KB page alignment (Play requirement for targetSdk 35+; NDK r28+ default, made
# explicit) + drop unreferenced sections.
# --strip-all: strip at LINK time. AGP's own strip step runs in :androidApp, which has
# no NDK configured (the NDK lives outside the space-containing SDK path and is wired
# only here, in :shared), so it printed "Unable to strip ... librunargon2.so" and
# shipped .debug_* + .symtab in the release .aab. Every other .so we ship arrives
# prebuilt and stripped; this keeps ours the same and independent of that step.
# The dynamic symbol table (the JNI export) is unaffected.
target_link_options(runargon2 PRIVATE
  -Wl,--strip-all
  -Wl,--gc-sections
  -Wl,-z,max-page-size=16384
  -Wl,-z,relro
  -Wl,-z,now
)
