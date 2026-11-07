package com.vg.run

import androidx.navigation.NavController

/**
 * Every navigation route in the app. The VALUES are the route strings the
 * NavHost has always used (ProtectionRouteTest / MoveWiringTest assert them), so
 * this object only gives them one spelling. Routes with an argument have a
 * pattern constant (for `composable(route = …)`) and a builder function.
 */
internal object Routes {
    const val SETUP = "setup"
    const val SETUP_MOVE = "setup_move"
    const val SETUP_PIN = "setup_pin"
    const val MOVE_IMPORT = "move_import"
    const val MOVE_EXPORT = "move_export"
    const val MOVE_FROZEN = "move_frozen"
    const val PIN = "pin"
    const val RECOVER = "recover"
    const val PROTECTION_SETUP = "protection_setup"
    const val PROTECTION_FORCED = "protection_forced"
    const val CONTACTS = "contacts"
    const val PROTECTION_LEVEL = "protection_level"
    const val CREATE_GROUP = "create_group"
    const val CHANGE_PIN = "change_pin"
    const val ADD_CONTACT = "add_contact"
    const val GROUP = "group/{groupId}"
    const val GROUP_INFO = "group_info/{groupId}"
    const val CONVERSATION = "conversation/{contactId}"

    fun group(id: String) = "group/$id"
    fun groupInfo(id: String) = "group_info/$id"
    fun conversation(id: String) = "conversation/$id"
}

/** Navigates to [route] and clears the WHOLE back stack (`popUpTo(0)`, inclusive). */
internal fun NavController.resetTo(route: String) =
    navigate(route) { popUpTo(0) { inclusive = true } }

/** Navigates to [route], popping the back stack up to and including [upTo]. */
internal fun NavController.navigateClearing(route: String, upTo: String) =
    navigate(route) { popUpTo(upTo) { inclusive = true } }

/**
 * Replaces the top back-stack entry with [route]: pops it, then navigates.
 * Same two calls, same order, as the hand-written pairs it replaced, so BACK
 * from [route] returns to whatever sat under the replaced entry.
 */
internal fun NavController.replaceTop(route: String) {
    popBackStack()
    navigate(route)
}
