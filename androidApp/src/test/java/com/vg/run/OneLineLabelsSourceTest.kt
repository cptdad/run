package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Short labels that must not be broken or cut: a tip tier's price stays on ONE line on both
 * platforms, and on iOS the tier name and the contact menu's "Add" memory button are not
 * truncated in a longer language.
 *
 * Found on a Pixel 7 and a Samsung A13, 2026-11-24, in the reference pictures of the Support
 * screen: with prices in kronor the white price label read "125,00 k / r" and "309,0 / 0 kr".
 * The Row measured the tier name first and handed the price what was left.
 *
 * SOURCE-LEVEL, like this file's siblings; comments are stripped before scanning.
 */
class OneLineLabelsSourceTest {

    @Test
    fun `android - the tier name yields and the price never wraps`() {
        val src = stripComments(File(repoRoot(), "androidApp/src/google/kotlin/com/vg/run/TipJar.kt").readText())
        val row = src.substringAfter("private fun TipTierRow(").substringBefore("private fun tierLabel(")
        assertTrue("precondition: TipTierRow found", row.contains("product.formattedPrice"))
        val label = row.substringAfter("tierLabel(product.productId)").substringBefore("Box(")
        assertTrue("the tier name must take the remaining width (Modifier.weight)", label.contains(".weight(1f)"))
        val price = row.substringAfter("product.formattedPrice").substringBefore(")\n        }")
        assertTrue("the price must be limited to one line", price.contains("maxLines = 1"))
        assertTrue("the price must not soft-wrap", price.contains("softWrap = false"))
    }

    @Test
    fun `ios - the price is one line at its own width`() {
        val src = File(repoRoot(), "iosApp/iosApp/SupportView.swift").readText()
        val price = src.substringAfter("Text(product.displayPrice)").substringBefore(".clipShape(Capsule())")
        assertTrue("precondition: the price label found", price.contains(".background(Color.runTextPrimary)"))
        assertTrue("the price must be limited to one line", price.contains(".lineLimit(1)"))
        assertTrue("the price must keep its own width", price.contains(".fixedSize(horizontal: true, vertical: false)"))
    }

    /** German, iPhone 12, 2026-11-24: "Spendier mir einen Kaf…" beside the price. */
    @Test
    fun `ios - a long tier name wraps instead of being cut`() {
        val src = File(repoRoot(), "iosApp/iosApp/SupportView.swift").readText()
        val label = src.substringAfter("Text(tierLabel(product.id))").substringBefore("Spacer()")
        assertTrue("the tier name must be allowed to grow downwards", label.contains(".fixedSize(horizontal: false, vertical: true)"))
    }

    /** German, iPhone 12, 2026-11-24: the contact menu's memory button read "Hinzufüg…". */
    @Test
    fun `ios - the contact menu's Add memory button keeps its width`() {
        val src = File(repoRoot(), "iosApp/iosApp/ContactListView.swift").readText()
        val button = src.substringAfter("L10n.contactListAddMemoryButton : L10n.contactListEditMemoryButton)")
            .substringBefore(".accessibilityIdentifier(\"menu_memory\")")
        assertTrue("precondition: the button found", button.contains(".lineLimit(1)"))
        assertTrue("alone in the row it must keep its own width", button.contains(".fixedSize(horizontal: c.mnemonic.isEmpty, vertical: false)"))
    }
}
