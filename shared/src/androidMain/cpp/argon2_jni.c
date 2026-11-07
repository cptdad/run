/*
 * JNI shim: com.vg.run.NativeArgon2.argon2idRaw -> argon2id_hash_raw, the same
 * entry point iOS calls from SwiftArgon2.swift, over the same vendored PHC sources.
 *
 * Contract (mirrors NativeArgon2.kt):
 *   - returns a NEW byte[outLen] holding the raw Argon2id (v1.3) tag;
 *   - throws IllegalArgumentException on a non-positive cost / length or an empty
 *     salt, and IllegalStateException("argon2id failed: <ARGON2 error> (rc=N)") on
 *     any non-zero argon2 return code. It never returns a partial or zero buffer,
 *     so the Kotlin caller can never mistake a failure for a derived key.
 *   - Our native copies of the password and of the output tag are wiped
 *     (memset + compiler barrier, which -O3 dead-store elimination cannot drop)
 *     on every path before they are freed. The Java arrays belong to the caller.
 *   - The 64 MiB Argon2 work area itself is scrubbed by the reference core
 *     (FLAG_clear_internal_memory = 1 in core.c -> clear_internal_memory on free).
 *
 * No logging here, on any path: inputs must never reach a log sink.
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"

static void wipe(void *p, size_t n) {
    if (p == NULL || n == 0) return;
    memset(p, 0, n);
    /* Compiler barrier: the buffer "escapes" into opaque asm that may read
     * memory, so the memset above is not a dead store and cannot be elided. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

static void throw_by_name(JNIEnv *env, const char *cls, const char *msg) {
    jclass c = (*env)->FindClass(env, cls);
    if (c != NULL) {
        (*env)->ThrowNew(env, c, msg);
        (*env)->DeleteLocalRef(env, c);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_vg_run_NativeArgon2_argon2idRaw(JNIEnv *env, jclass clazz,
                                         jbyteArray password, jbyteArray salt,
                                         jint memoryKib, jint iterations,
                                         jint parallelism, jint outLen) {
    (void) clazz;
    if (password == NULL || salt == NULL) {
        throw_by_name(env, "java/lang/NullPointerException", "argon2id: null input");
        return NULL;
    }
    if (memoryKib <= 0 || iterations <= 0 || parallelism <= 0 || outLen <= 0) {
        throw_by_name(env, "java/lang/IllegalArgumentException",
                      "argon2id: cost and output length must be positive");
        return NULL;
    }
    const jsize pwdLen = (*env)->GetArrayLength(env, password);
    const jsize saltLen = (*env)->GetArrayLength(env, salt);
    if (saltLen <= 0) {
        throw_by_name(env, "java/lang/IllegalArgumentException", "argon2id: salt must not be empty");
        return NULL;
    }

    /* +1 so a zero-length password still yields a non-NULL pointer. */
    uint8_t *pwd = (uint8_t *) malloc((size_t) pwdLen + 1);
    uint8_t *slt = (uint8_t *) malloc((size_t) saltLen);
    uint8_t *out = (uint8_t *) malloc((size_t) outLen);
    if (pwd == NULL || slt == NULL || out == NULL) {
        free(pwd); free(slt); free(out); /* nothing copied yet: no secret to wipe */
        throw_by_name(env, "java/lang/OutOfMemoryError", "argon2id: buffer allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, password, 0, pwdLen, (jbyte *) pwd);
    (*env)->GetByteArrayRegion(env, salt, 0, saltLen, (jbyte *) slt);

    const int rc = argon2id_hash_raw((uint32_t) iterations, (uint32_t) memoryKib,
                                     (uint32_t) parallelism,
                                     pwd, (size_t) pwdLen,
                                     slt, (size_t) saltLen,
                                     out, (size_t) outLen);

    wipe(pwd, (size_t) pwdLen + 1);
    free(pwd);
    free(slt);

    if (rc != ARGON2_OK) {
        wipe(out, (size_t) outLen);
        free(out);
        char msg[160];
        const char *name = argon2_error_message(rc);
        snprintf(msg, sizeof msg, "argon2id failed: %s (rc=%d)", name ? name : "unknown", rc);
        throw_by_name(env, "java/lang/IllegalStateException", msg);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, outLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, outLen, (const jbyte *) out);
    }
    /* NewByteArray failure leaves an OutOfMemoryError pending: return NULL with it. */
    wipe(out, (size_t) outLen);
    free(out);
    return result;
}
