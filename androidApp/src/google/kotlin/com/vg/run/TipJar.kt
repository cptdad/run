package com.vg.run

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.collectAsState
import com.android.billingclient.api.*
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

// ---------------------------------------------------------------------------
// TipJar — the Google Play Billing tip UI (TipJarBody) rendered inside the Support
// Rún modal (DonateModal shows it directly; there are no tabs).
//
// One-time CONSUMABLE products (so a supporter can tip again and again). The
// app only references the product IDs below; the actual localized prices and
// the products themselves are configured in the Play Console (Monetize →
// In-app products). Until those exist on a build distributed through a Play
// track (or a license-tester install), queryProductDetails returns nothing and
// the body shows a graceful "unavailable" state — never a crash.
//
// No server, no payment processor: Google is processor + bank, exactly like
// the iOS StoreKit plan. A purchase is consumed immediately on success
// (consume also acknowledges it), so nothing is owned and it can be repeated.
// ---------------------------------------------------------------------------

/** Tip product IDs — create these as consumable one-time products in Play
 *  Console, priced in SEK (base currency; other regions auto-convert). The
 *  live price comes from Play, not here — these are the intended tiers.
 *  Order = display order. */
private val TIP_TIERS = listOf(
    "tip_small",   // 19 SEK  — Buy me a coffee
    "tip_medium",  // 49 SEK  — Small tip
    "tip_large",   // 99 SEK  — Generous tip
    "tip_xl",      // 999 SEK — You're a legend
)

/** A purchasable tier resolved from Play (localized price comes from Play). */
data class TipProduct(
    val productId: String,
    val title: String,
    val formattedPrice: String,
    val details: ProductDetails,
)

data class TipState(
    val connecting: Boolean = true,
    /** True once we've heard back from Play (success or failure) at least once. */
    val resolved: Boolean = false,
    val products: List<TipProduct> = emptyList(),
    /** Set briefly after a successful tip — drives the thank-you flash. */
    val thanked: Boolean = false,
    /** Non-null when billing is unavailable / the query failed. */
    val error: String? = null,
)

/**
 * Owns the BillingClient for the lifetime of the Support modal. Connects,
 * queries the tip products, launches the purchase flow, and consumes
 * successful purchases so they can be repeated. All callbacks are bridged to
 * [state] for Compose to observe.
 */
class TipBillingManager(context: Context) {

    // Stored (not just a constructor param) so the member functions below —
    // reached from Billing callbacks, not composable context — can resolve
    // localized error copy via getString.
    private val appContext = context.applicationContext

    private val _state = MutableStateFlow(TipState())
    val state: StateFlow<TipState> = _state.asStateFlow()

    private val purchasesListener = PurchasesUpdatedListener { result, purchases ->
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> purchases?.forEach { consume(it) }
            BillingClient.BillingResponseCode.USER_CANCELED -> { /* silent — user backed out */ }
            else -> _state.value = _state.value.copy(
                error = appContext.getString(R.string.tip_error_purchase_failed),
            )
        }
    }

    private val client: BillingClient = BillingClient.newBuilder(context)
        .setListener(purchasesListener)
        .enablePendingPurchases(
            PendingPurchasesParams.newBuilder().enableOneTimeProducts().build()
        )
        .build()

    fun start() {
        client.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    reconcileUnconsumedPurchases()
                    queryProducts()
                } else {
                    _state.value = _state.value.copy(
                        connecting = false, resolved = true,
                        error = appContext.getString(R.string.tip_error_unavailable_device),
                    )
                }
            }

            override fun onBillingServiceDisconnected() {
                // Leave the last good state; a fresh modal open retries.
                _state.value = _state.value.copy(connecting = false)
            }
        })
    }

    /**
     * Reconcile purchases Play already completed but
     * this app never consumed.
     *
     * The window is wide open here: Play's payment sheet is full-screen, so it
     * covers MainActivity → `onStop` → `finishAndRemoveTask()` (the whole-session
     * teardown) → this manager is disposed mid-purchase and
     * [purchasesListener] never fires. The purchase token then sits unconsumed and
     * Google AUTO-REFUNDS it after ~3 days: the user paid, saw no thanks, and the
     * tip silently reverses days later. `queryPurchasesAsync` on every connect is
     * the documented fix — it returns exactly those completed-but-unconsumed
     * purchases, and [consume] is idempotent for anything already handled.
     */
    private fun reconcileUnconsumedPurchases() {
        val params = QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.INAPP)
            .build()
        client.queryPurchasesAsync(params) { result, purchases ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK) return@queryPurchasesAsync
            // consume() already filters on PURCHASED, so PENDING tokens are left
            // for Play to resolve rather than consumed early.
            purchases.forEach { consume(it) }
        }
    }

    private fun queryProducts() {
        val products = TIP_TIERS.map { id ->
            QueryProductDetailsParams.Product.newBuilder()
                .setProductId(id)
                .setProductType(BillingClient.ProductType.INAPP)
                .build()
        }
        val params = QueryProductDetailsParams.newBuilder().setProductList(products).build()
        client.queryProductDetailsAsync(params) { result, details ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                _state.value = _state.value.copy(
                    connecting = false, resolved = true,
                    error = appContext.getString(R.string.tip_error_load_failed),
                )
                return@queryProductDetailsAsync
            }
            // Preserve TIP_TIERS order regardless of Play's response order.
            // Billing 8.0.0: the listener's 2nd arg is QueryProductDetailsResult,
            // not List<ProductDetails> — read the list out of it.
            val byId = details.productDetailsList.associateBy { it.productId }
            val resolved = TIP_TIERS.mapNotNull { id ->
                val pd = byId[id] ?: return@mapNotNull null
                val price = pd.oneTimePurchaseOfferDetails?.formattedPrice ?: return@mapNotNull null
                TipProduct(id, pd.title, price, pd)
            }
            _state.value = _state.value.copy(
                connecting = false, resolved = true, products = resolved,
                error = if (resolved.isEmpty()) appContext.getString(R.string.tip_error_not_configured) else null,
            )
        }
    }

    /** Launch Play's purchase sheet for [product]. Must be called with the
     *  hosting Activity (Play renders its UI on top of it). */
    fun buy(activity: Activity, product: TipProduct) {
        _state.value = _state.value.copy(error = null, thanked = false)
        val params = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(
                listOf(
                    BillingFlowParams.ProductDetailsParams.newBuilder()
                        .setProductDetails(product.details)
                        .build()
                )
            )
            .build()
        // launchBillingFlow returns synchronously; a non-OK code means Play never
        // presented its sheet (e.g. service unavailable). Surface it instead of a
        // silent no-op — the old symptom was a tap that did nothing.
        val result = client.launchBillingFlow(activity, params)
        if (result.responseCode != BillingClient.BillingResponseCode.OK) {
            _state.value = _state.value.copy(error = appContext.getString(R.string.tip_error_checkout_failed))
        }
    }

    /** Surface a client-side failure to open checkout (e.g. no hosting Activity). */
    fun reportBuyError() {
        _state.value = _state.value.copy(error = appContext.getString(R.string.tip_error_checkout_failed))
    }

    private fun consume(purchase: Purchase) {
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) return
        val params = ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()
        client.consumeAsync(params) { _, _ ->
            // Consumed (and thereby acknowledged) — the tip is complete and can
            // be given again. Show gratitude regardless of the consume result:
            // the money already moved; a consume hiccup only delays repeatability.
            _state.value = _state.value.copy(thanked = true)
        }
    }

    fun stop() {
        try { client.endConnection() } catch (_: Exception) { /* already torn down */ }
    }
}

/**
 * Tip-jar body rendered in the "Tip" tab of [DonateModal] (the "Crypto" tab is
 * its peer). Owns a [TipBillingManager] for the duration it's composed (connect
 * on appear, disconnect on dispose).
 */
@Composable
fun TipJarBody() {
    val context = LocalContext.current
    val manager = remember { TipBillingManager(context) }
    DisposableEffect(Unit) {
        manager.start()
        onDispose { manager.stop() }
    }
    val state by manager.state.collectAsState()

    Column(
        modifier = Modifier.fillMaxWidth().testTag("tip_jar_body"),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        when {
            state.thanked -> {
                Text(
                    text = stringResource(R.string.tip_thank_you),
                    color = RunWhite,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("tip_thanks"),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.tip_thank_you_body),
                    color = RunGrey, fontSize = 13.sp, textAlign = TextAlign.Center,
                )
            }

            state.connecting && !state.resolved -> {
                Text(stringResource(R.string.common_loading), color = RunGrey, fontSize = 14.sp,
                    modifier = Modifier.testTag("tip_loading"))
            }

            state.products.isEmpty() -> {
                Text(
                    text = state.error ?: stringResource(R.string.tip_unavailable_fallback),
                    color = RunGrey, fontSize = 14.sp, textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("tip_unavailable"),
                )
            }

            else -> {
                state.products.forEach { product ->
                    TipTierRow(product = product, onTip = {
                        // The Support modal is a Compose Dialog, so LocalContext here
                        // is a ContextWrapper, NOT the Activity — a plain `as? Activity`
                        // is null and the tap no-ops (the reported bug). Walk the wrapper
                        // chain to the hosting Activity that launchBillingFlow needs.
                        val activity = context.findActivity()
                        if (activity != null) manager.buy(activity, product) else manager.reportBuyError()
                    })
                    Spacer(Modifier.height(10.dp))
                }
                state.error?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, color = RunGrey, fontSize = 12.sp, textAlign = TextAlign.Center)
                }
            }
        }
    }
}

/** One tip tier: a friendly label + the localized Play price, tap to purchase. */
@Composable
private fun TipTierRow(product: TipProduct, onTip: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(RunBlack)
            .clickable(onClick = onTip)
            .testTag("tip_tier_${product.productId}")
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(tierLabel(product.productId), color = RunWhite, fontSize = 15.sp)
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(RunWhite)
                .padding(horizontal = 18.dp, vertical = 8.dp),
        ) {
            Text(product.formattedPrice, color = RunBlack, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
        }
    }
}

/** Friendly tier names (the Play product title often carries the app name). */
@Composable
private fun tierLabel(productId: String): String = when (productId) {
    "tip_small"  -> stringResource(R.string.tip_tier_small)
    "tip_medium" -> stringResource(R.string.tip_tier_medium)
    "tip_large"  -> stringResource(R.string.tip_tier_large)
    "tip_xl"     -> stringResource(R.string.tip_tier_xl)
    else         -> stringResource(R.string.donate_tab_tip)
}

