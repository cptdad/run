package com.vg.run

import android.content.Context

/**
 * Android resolver for [platformString]. Installed ONCE per process from
 * `RunApplication.onCreate` (which runs in every process, including the FCM /
 * UnifiedPush wake processes) with the generated `L10nKeys.strings` map — compile-time
 * `R.string` references, never `Resources.getIdentifier`, because release builds run
 * `shrinkResources` and the shrinker strips strings only reachable by name.
 */
object AndroidStrings {
    @Volatile private var appContext: Context? = null
    @Volatile private var ids: Map<String, Int> = emptyMap()

    /**
     * API 29–32 app-language override hook (`AppLocale.wrap`): the application
     * context does not follow a per-app locale below API 33, so the app installs a
     * wrapper that re-configures the context. Identity on 33+ (LocaleManager keeps
     * the app context in sync itself).
     */
    @Volatile var contextWrapper: (Context) -> Context = { it }

    fun install(context: Context, stringIds: Map<String, Int>) {
        appContext = context.applicationContext
        ids = stringIds
    }

    internal fun resolve(key: String, args: Array<out Any?>): String? {
        val base = appContext ?: return null
        val id = ids[key] ?: return null
        val ctx = contextWrapper(base)
        return try {
            if (args.isEmpty()) ctx.getString(id) else ctx.getString(id, *args)
        } catch (_: Throwable) {
            null
        }
    }
}

actual fun platformString(key: String, vararg args: Any?): String {
    platformStringOverride?.let { return it(key, args) }
    return AndroidStrings.resolve(key, args) ?: key
}
