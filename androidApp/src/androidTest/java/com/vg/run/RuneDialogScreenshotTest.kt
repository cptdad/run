package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunTheme
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.io.FileOutputStream

/**
 * Renders the Rune dialog chrome and writes PNGs to the app's external files
 * dir so the result can be eyeballed against the artist mock (colours,
 * uppercase Metamorphous, hairlines, action order). Not an assertion test —
 * a visual harness. The chrome composables are rendered directly rather than
 * through [RuneDialog] because a Dialog renders in a separate window that
 * createComposeRule cannot capture.
 */
class RuneDialogScreenshotTest {

    @get:Rule
    val rule = createComposeRule()

    private fun shoot(name: String, content: @Composable () -> Unit) {
        rule.setContent {
            RunTheme {
                Box(
                    modifier = Modifier.fillMaxSize().background(RunBlack),
                    contentAlignment = Alignment.Center,
                ) { content() }
            }
        }
        rule.waitForIdle()
        val bmp = rule.onRoot().captureToImage().asAndroidBitmap()
        val instr = InstrumentationRegistry.getInstrumentation()
        val out = File(instr.targetContext.getExternalFilesDir(null)!!, "$name.png")
        FileOutputStream(out).use { bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
        // AGP uninstalls both APKs when the run ends, which takes the app's
        // external files dir with it — copy to /data/local/tmp (shell-owned,
        // survives the uninstall) so the PNG can be pulled afterwards.
        instr.uiAutomation
            .executeShellCommand("cp ${out.absolutePath} /data/local/tmp/$name.png")
            .use { fd -> java.io.FileInputStream(fd.fileDescriptor).use { it.readBytes() } }
    }

    /** The mock's own dialog: consent gate, affirmative first (APPROVE | DECLINE). */
    @Test
    fun consentDialog() = shoot("rune_consent") {
        RuneCard(modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)) {
            RuneCardBody {
                RuneDialogMessage(
                    "{introducer} wants to introduce you to “{peer}”. Approve to add them as a contact."
                )
            }
            RuneActionRow(
                listOf(
                    RuneDialogAction("Approve", onClick = {}),
                    runeSecondary("Decline") {},
                )
            )
        }
    }

    /** Destructive confirm: dismissive first, destructive LAST (safety rule). */
    @Test
    fun destructiveDialog() = shoot("rune_destructive") {
        RuneCard(modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)) {
            RuneCardBody {
                RuneDialogTitle("Delete Silent Fox?")
                RuneDialogMessage("All messages will be permanently destroyed")
            }
            RuneActionRow(
                listOf(
                    runeSecondary("Cancel") {},
                    runeDestructive("Delete") {},
                )
            )
        }
    }
}
