package com.vg.run

// ---------------------------------------------------------------------------
// AndroidMoveSessionControl — the platform half of "Move to new device"
// (docs/device-move.md), i.e. what MoveManager is lent by the session layer.
//
// Every method is a one-line delegate to RunViewModel; the reasoning for each
// one lives next to the implementation (moveQuiesceSession / moveResumeSession /
// moveTransport in RunViewModel; the push unregister in
// PushRegistrationCoordinator.unregisterForMoveAwaiting, behind the VM's
// moveUnregisterPushAwaiting delegate). Two reasons this is
// a separate file rather than an `object :` inside the ViewModel:
//
//  1. RunViewModel.kt must not contain the token `suspend fun
//     unregisterPushBestEffort(` — PushSessionBookkeepingRaceSourceTest pins
//     that file's unregister as NON-suspend, because the crypto-erase-first
//     wipe path calls it synchronously and a suspension point there would make
//     the erase wait on whatever holds pushRefreshMutex. An interface override
//     with the same name would read as that exact token in the same file.
//  2. It keeps the seam visible: this class is the complete list of what the
//     move is allowed to do to the session.
//
// The iOS sibling is the equivalent seam in IosAppController/AppState.
// ---------------------------------------------------------------------------

/**
 * Holds the [RunViewModel] directly. That is not a leak: the ViewModel owns this
 * object (`moveSession`), which is the same lifetime, and every call has to run
 * against the CURRENT vault/transport rather than a snapshot taken at
 * construction.
 */
internal class AndroidMoveSessionControl(
    private val vm: RunViewModel,
) : MoveSessionControl {

    override suspend fun unregisterPushBestEffort() = vm.moveUnregisterPushAwaiting()

    override suspend fun quiesce() = vm.moveQuiesceSession()

    override suspend fun resume() = vm.moveResumeSession()

    override fun transport(): MoveTransport? = vm.moveTransport()
}
