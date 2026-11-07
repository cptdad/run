package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * DNS-leak guard: hostIsOnion must classify the URL's
 * authority HOST, not match ".onion" anywhere in the string. The direct
 * transport refuses true cases; the SOCKS transport refuses false cases.
 */
class HttpHostGuardTest {

    @Test fun onionHosts_areDetected() {
        assertTrue(hostIsOnion("http://abcdefghijklmnop.onion/inbox/x"))
        assertTrue(hostIsOnion("http://abcdefghijklmnop.onion"))            // no path
        assertTrue(hostIsOnion("http://abcdefghijklmnop.onion:80/x"))       // with port
        assertTrue(hostIsOnion("https://abc.onion/inbox/123?y=1"))
        assertTrue(hostIsOnion("http://user@abc.onion/x"))                  // userinfo
        assertTrue(hostIsOnion("http://ABC.ONION/x"))                       // case-insensitive
    }

    @Test fun clearnetHosts_areNotOnion() {
        assertFalse(hostIsOnion("http://localhost:8080"))
        assertFalse(hostIsOnion("http://10.0.2.2:8080/inbox/x"))
        assertFalse(hostIsOnion("https://example.com/path"))
        assertFalse(hostIsOnion("http://127.0.0.1:9050/"))
    }

    /** The whole point: ".onion" in the path/query must NOT count. */
    @Test fun onionInPathOrQuery_doesNotCount() {
        assertFalse(hostIsOnion("https://example.com/download/guide.onion"))
        assertFalse(hostIsOnion("https://example.com/?redirect=abc.onion"))
        assertFalse(hostIsOnion("https://onion.example.com/x"))            // subdomain label, host is example.com-ish
    }

    @Test fun malformed_isNotOnion() {
        assertFalse(hostIsOnion(""))
    }

    /** Hardened edge cases: scheme-less authorities are now
     *  parsed, and a trailing-dot FQDN is still recognised as .onion — both were
     *  previously mis-classified onto the unguarded direct path. */
    @Test fun hardenedEdgeCases_areOnion() {
        assertTrue(hostIsOnion("abc.onion"))             // scheme-less host
        assertTrue(hostIsOnion("abc.onion:8080/inbox"))  // scheme-less host:port/path
        assertTrue(hostIsOnion("http://abc.onion./x"))   // trailing-dot FQDN
        assertTrue(hostIsOnion("http://abc.onion.:80/x"))
        assertTrue(hostIsOnion("http://user@abc.onion.:80/x?q=1#f"))
    }

    @Test fun hardenedEdgeCases_clearnetStays() {
        assertFalse(hostIsOnion("example.com/abc.onion"))  // scheme-less, .onion in path
        assertFalse(hostIsOnion("example.com:443/x"))
        assertFalse(hostIsOnion("http://example.com./x"))  // trailing-dot clearnet
    }
}
