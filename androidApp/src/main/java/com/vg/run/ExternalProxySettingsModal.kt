package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RuneDanger
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// ExternalProxySettingsModal — Settings → External Tor proxy (external SOCKS
// proxy mode, ExternalTorProxy.kt commonMain; RunViewModel's "EXTERNAL SOCKS
// PROXY MODE" block owns the behaviour).
//
// Toggle + IP + port + Save. Validation is the shared commonMain rule
// (ExternalTorProxy.validateInput) so both platforms accept and refuse exactly
// the same input; a LAN address is allowed with an inline warning. A save
// only persists for the NEXT launch — nothing switches live — and the modal
// says so. NOT relay-gated: this is how a user fixes a proxy that is down.
//
// a11y ids (identical on iOS): settings_ext_proxy_toggle,
// settings_ext_proxy_host, settings_ext_proxy_port, settings_ext_proxy_save,
// ext_proxy_status, settings_ext_proxy_done, settings_ext_proxy_lan_warning, settings_ext_proxy_loopback_warning (Android-only),
// settings_ext_proxy_error, settings_ext_proxy_saved,
// settings_ext_proxy_next_launch (Android-only: ext_proxy_dialog). The row that
// opens this is `settings_ext_proxy` (ContactListScreen).
// ---------------------------------------------------------------------------

@Composable
fun ExternalProxySettingsModal(viewModel: RunViewModel, onClose: () -> Unit) {
    val saved = remember { viewModel.savedExternalProxy() }
    var enabled by remember { mutableStateOf(saved != null) }
    var hostText by remember {
        // Shown without brackets; ExternalTorProxy accepts either form.
        mutableStateOf(saved?.host ?: "")
    }
    var portText by remember { mutableStateOf(saved?.port?.toString() ?: "") }
    var error by remember { mutableStateOf(ExternalTorProxy.InputError.NONE) }
    var saving by remember { mutableStateOf(false) }
    var savedNote by remember { mutableStateOf(false) }
    var saveFailed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val status by viewModel.externalProxyStatus.collectAsState()

    val showLanWarning = enabled && ExternalTorProxy.isLan(hostText)
    // Android only: loopback can be squatted by another app while the proxy app is down.
    val showLoopbackWarning = enabled && ExternalTorProxy.classify(hostText.trim().removeSurrounding("[", "]")) == HostClass.LOOPBACK

    fun onSave() {
        saveFailed = false
        savedNote = false
        val config: ExternalTorProxyConfig?
        if (enabled) {
            val e = ExternalTorProxy.validateInput(hostText, portText)
            error = e
            if (e != ExternalTorProxy.InputError.NONE) return
            config = ExternalTorProxy.fromInput(hostText, portText) ?: return
        } else {
            config = null
        }
        saving = true
        scope.launch {
            val ok = withContext(Dispatchers.IO) { viewModel.saveExternalProxy(config) }
            saving = false
            if (ok) savedNote = true else saveFailed = true
        }
    }

    RuneDialog(
        onDismissRequest = if (saving) null else onClose,
        testTag = "ext_proxy_dialog",
        title = stringResource(R.string.ext_proxy_title),
        content = {
            Text(
                text = stringResource(R.string.ext_proxy_description),
                style = MaterialTheme.typography.bodySmall,
                color = RunGrey,
                textAlign = TextAlign.Center,
            )
            ExternalProxyStatusText(status, connectingScreen = false)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = stringResource(R.string.ext_proxy_toggle),
                    color = RunWhite,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(12.dp))
                Switch(
                    checked = enabled,
                    onCheckedChange = {
                        enabled = it
                        error = ExternalTorProxy.InputError.NONE
                        savedNote = false
                    },
                    enabled = !saving,
                    modifier = Modifier.testTag("settings_ext_proxy_toggle"),
                )
            }
            if (enabled) {
                ProxyField(
                    label = stringResource(R.string.ext_proxy_host_label),
                    value = hostText,
                    onValueChange = {
                        // No trimming: the strict rule applies to input too.
                        hostText = it.take(MAX_FIELD_CHARS)
                        error = ExternalTorProxy.InputError.NONE
                        savedNote = false
                    },
                    keyboardType = KeyboardType.Password,
                    testTag = "settings_ext_proxy_host",
                    enabled = !saving,
                )
                ProxyField(
                    label = stringResource(R.string.ext_proxy_port_label),
                    value = portText,
                    onValueChange = {
                        portText = it.take(5)
                        error = ExternalTorProxy.InputError.NONE
                        savedNote = false
                    },
                    keyboardType = KeyboardType.NumberPassword,
                    testTag = "settings_ext_proxy_port",
                    enabled = !saving,
                )
                when (error) {
                    ExternalTorProxy.InputError.HOST -> InlineNote(stringResource(R.string.ext_proxy_error_host), "settings_ext_proxy_error", danger = true)
                    ExternalTorProxy.InputError.PORT -> InlineNote(stringResource(R.string.ext_proxy_error_port), "settings_ext_proxy_error", danger = true)
                    ExternalTorProxy.InputError.NONE -> Unit
                }
                if (showLanWarning) {
                    InlineNote(stringResource(R.string.ext_proxy_lan_warning), "settings_ext_proxy_lan_warning", danger = false)
                }
                if (showLoopbackWarning) {
                    InlineNote(stringResource(R.string.ext_proxy_loopback_warning), "settings_ext_proxy_loopback_warning", danger = false)
                }
            }
            // The save outcome sits at the bottom of a scrollable dialog that
            // overflows at large font scales (the toggled-on form + warnings), so
            // a user — and UiAutomator, which sees only on-screen nodes — would
            // never see "Saved". Scroll it into view whenever the outcome changes.
            val outcomeView = remember { BringIntoViewRequester() }
            LaunchedEffect(savedNote, saveFailed) {
                if (savedNote || saveFailed) outcomeView.bringIntoView()
            }
            Column(Modifier.bringIntoViewRequester(outcomeView)) {
                if (saveFailed) {
                    InlineNote(stringResource(R.string.ext_proxy_error_save), "settings_ext_proxy_error", danger = true)
                }
                InlineNote(
                    stringResource(if (savedNote) R.string.ext_proxy_saved else R.string.ext_proxy_next_launch),
                    if (savedNote) "settings_ext_proxy_saved" else "settings_ext_proxy_next_launch",
                    danger = false,
                )
            }
        },
        actions = listOf(
            runeSecondary(stringResource(R.string.common_done), testTag = "settings_ext_proxy_done") {
                if (!saving) onClose()
            },
            RuneDialogAction(
                label = stringResource(R.string.common_save),
                testTag = "settings_ext_proxy_save",
                enabled = !saving,
                onClick = ::onSave,
            ),
        ),
    )
}

/**
 * The one status line for external proxy mode, shared by the settings modal
 * and the connecting screen (ContactListScreen) so both say the same thing.
 * Renders nothing while the mode is off. [connectingScreen] picks the
 * connecting-screen wording for the pre-answer state (`ext_proxy_connecting`)
 * over the settings wording (`ext_proxy_status_checking`) — same as iOS.
 */
@Composable
fun ExternalProxyStatusText(
    status: RunViewModel.ExternalProxyStatus,
    modifier: Modifier = Modifier,
    connectingScreen: Boolean = true,
) {
    val res = when (status) {
        RunViewModel.ExternalProxyStatus.OFF -> return
        RunViewModel.ExternalProxyStatus.INVALID -> R.string.ext_proxy_status_invalid
        RunViewModel.ExternalProxyStatus.UNREADABLE -> R.string.ext_proxy_status_unreadable
        RunViewModel.ExternalProxyStatus.CHECKING ->
            if (connectingScreen) R.string.ext_proxy_connecting else R.string.ext_proxy_status_checking
        RunViewModel.ExternalProxyStatus.REACHABLE -> R.string.ext_proxy_status_reachable
        RunViewModel.ExternalProxyStatus.UNREACHABLE -> R.string.ext_proxy_status_unreachable
    }
    val bad = status == RunViewModel.ExternalProxyStatus.UNREACHABLE ||
        status == RunViewModel.ExternalProxyStatus.INVALID ||
        status == RunViewModel.ExternalProxyStatus.UNREADABLE
    Text(
        text = stringResource(res),
        style = MaterialTheme.typography.bodySmall,
        color = if (bad) RuneDanger else RunGrey,
        textAlign = TextAlign.Center,
        modifier = modifier.testTag("ext_proxy_status"),
    )
}

private const val MAX_FIELD_CHARS = 32

@Composable
private fun ProxyField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    keyboardType: KeyboardType,
    testTag: String,
    enabled: Boolean,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = label, color = RunGrey, fontSize = 12.sp)
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(RunSurfaceAlt)
                .padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            // The proxy host/port identifies the user's network: the IME must not
            // learn it or offer it back as a suggestion.
            NoPersonalizedLearning {
                BasicTextField(
                    value = value,
                    onValueChange = onValueChange,
                    singleLine = true,
                    enabled = enabled,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(color = RunWhite),
                    cursorBrush = SolidColor(RunWhite),
                    // Autocorrect off; the text itself stays visible (no
                    // visualTransformation).
                    keyboardOptions = KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(testTag),
                )
            }
        }
    }
}

@Composable
private fun InlineNote(text: String, testTag: String, danger: Boolean) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = if (danger) RuneDanger else RunGrey,
        textAlign = TextAlign.Center,
        modifier = Modifier.testTag(testTag),
    )
}
