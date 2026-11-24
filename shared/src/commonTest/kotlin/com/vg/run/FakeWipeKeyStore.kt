package com.vg.run

/**
 * The injected key-store adapter of the RÚN-02 tests: every [WipeItem] answers a
 * scripted sequence of results — DELETED, ALREADY_ABSENT, UNRESOLVED or a throw —
 * independently of every other item, and every call is recorded in order.
 *
 * A script is consumed one step per call; once exhausted its LAST step repeats
 * (so "fails forever" is one step). An item with no script answers DELETED.
 */
internal class FakeWipeKeyStore(var protectedData: Boolean = true) : WipeKeyStore {

    sealed class Step {
        data class Answer(val result: EraseResult) : Step()
        data class Throw(val error: Exception) : Step()
    }

    private val scripts = mutableMapOf<WipeItem, MutableList<Step>>()
    val calls = mutableListOf<WipeItem>()

    fun script(item: WipeItem, vararg steps: Step) {
        scripts[item] = steps.toMutableList()
    }

    fun callsFor(item: WipeItem): Int = calls.count { it == item }

    override fun protectedDataAvailable(): Boolean = protectedData

    override fun erase(item: WipeItem): EraseResult {
        calls += item
        val q = scripts[item] ?: return EraseResult(EraseOutcome.DELETED, 0)
        val step = if (q.size > 1) q.removeAt(0) else q.first()
        return when (step) {
            is Step.Answer -> step.result
            is Step.Throw -> throw step.error
        }
    }

    companion object {
        fun ok(status: Int = 0) = Step.Answer(EraseResult(EraseOutcome.DELETED, status))
        fun absent(status: Int = -25300) = Step.Answer(EraseResult(EraseOutcome.ALREADY_ABSENT, status))
        fun fail(status: Int = -25308) = Step.Answer(EraseResult(EraseOutcome.UNRESOLVED, status))
        fun boom() = Step.Throw(IllegalStateException("adapter exploded"))
    }
}
