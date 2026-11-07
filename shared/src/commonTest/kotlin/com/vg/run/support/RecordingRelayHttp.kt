package com.vg.run

/**
 * Recording [RelayHttp] that replays a FIFO script: each POST / PUT / GET /
 * DELETE takes the next scripted [HttpResult], whatever its route.
 *
 * Models: the four base verbs, in call order ([calls]); an exhausted script
 * answers `-1 "no scripted reply"` (a transport failure).
 *
 * Does NOT model: routing (a reply meant for one call can be eaten by another;
 * use [FakeRelayHttp] or a route-keyed fake when that matters), inbox state, the
 * PoW mint ([MintingRelay]) or any defaulted overload beyond what the interface
 * forwards (the abort / first-byte / isolation forms reach the three-argument
 * [get] through the interface defaults).
 */
internal class RecordingRelayHttp(
    private val replies: MutableList<HttpResult> = mutableListOf(),
) : RelayHttp {
    data class Call(val method: String, val url: String, val body: ByteArray, val headers: Map<String, String>)
    val calls = mutableListOf<Call>()

    fun script(vararg results: HttpResult) { replies.addAll(results) }

    private fun next(): HttpResult =
        if (replies.isNotEmpty()) replies.removeAt(0)
        else HttpResult(code = -1, body = "no scripted reply", isSuccess = false)

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add(Call("POST", url, body, headers))
        return next()
    }
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add(Call("PUT", url, body, headers))
        return next()
    }
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add(Call("GET", url, ByteArray(0), headers))
        return next()
    }
    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add(Call("DELETE", url, ByteArray(0), headers))
        return next()
    }
}
