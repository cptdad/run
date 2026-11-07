package com.vg.run

// Relay traffic goes through Tor: Tor is required AND a relay is configured.
// Reads [RelayConfig.BASE_URL] at call time (the address race may switch it).
// The second half is implied today (`isTorRequired` is false for an empty slot
// 1) and kept so the semantics equal the call sites this replaced
// (`isTorRequired && BASE_URL.isNotEmpty()`). Its own file because an `expect
// object` member cannot carry a common body. Swift:
// `RelayRoutingKt.relayRoutesViaTor()`.
fun relayRoutesViaTor(): Boolean = RelayConfig.isTorRequired && RelayConfig.BASE_URL.isNotEmpty()
