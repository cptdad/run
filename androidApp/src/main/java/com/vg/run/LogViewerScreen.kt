package com.vg.run

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType

// ---------------------------------------------------------------------------
// LogViewerScreen — in-app log viewer for debugging.
//
// Shows the shared LogBuffer contents with filtering, copy, and clear.
// Reached via the hidden DEBUG 5-tap gesture on the contact list (ContactListScreen),
// not a PIN-gated tab.
//
// Debug builds only; not shipped in release (English literals, not localised).
// ---------------------------------------------------------------------------

@Composable
fun LogViewerScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    var filter by remember { mutableStateOf("") }
    var entries by remember { mutableStateOf(LogBuffer.getAll()) }
    val listState = rememberLazyListState()

    val filtered = remember(entries, filter) {
        if (filter.isBlank()) entries
        else {
            val f = filter.lowercase()
            entries.filter {
                it.tag.lowercase().contains(f) || it.message.lowercase().contains(f)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(RunBlack)
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding()
    ) {
        // Toolbar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Logs (${filtered.size})",
                color = RunGrey,
                fontSize = 13.sp
            )
            Spacer(Modifier.weight(1f))

            // Copy all
            IconButton(onClick = {
                // Sensitive, so the OS hides the clipboard preview and other apps
                // are discouraged from reading buffered metadata off it. Not
                // auto-cleared: the logs are copied to be pasted somewhere else.
                SensitiveClipboard.copy(context, "logs", LogBuffer.asText(), clearAfterMs = null)
                Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
            }) {
                Text("Copy", color = RunWhite, fontSize = 12.sp)
            }

            // Clear
            IconButton(onClick = {
                LogBuffer.clear()
                entries = emptyList()
            }) {
                Text("Clear", color = Color.Red, fontSize = 12.sp)
            }

            // Close
            IconButton(onClick = onClose) {
                Text("✕", color = RunWhite, fontSize = 16.sp)
            }
        }

        // Filter
        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            placeholder = { Text("Filter logs...", color = RunGrey, fontSize = 12.sp) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp),
            singleLine = true,
            // KeyboardType.Password so the IME doesn't learn/sync the
            // log-filter query (may contain a contact-id fragment) — parity with the
            // other 6 editable Android fields + iOS's autocorrectionDisabled.
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password
            ),
            textStyle = LocalTextStyle.current.copy(color = RunWhite, fontSize = 12.sp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = RunGrey,
                unfocusedBorderColor = Color(0xFF333333)
            )
        )

        Spacer(Modifier.height(4.dp))

        // Log entries
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 8.dp)
        ) {
            items(filtered) { entry ->
                Text(
                    text = entry.formatted(),
                    color = when (entry.level) {
                        "E" -> Color.Red
                        "W" -> Color.Yellow
                        else -> Color(0xFFB0B0B0)
                    },
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 12.sp,
                    modifier = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }

    // Auto-scroll to bottom on new entries
    LaunchedEffect(filtered.size) {
        if (filtered.isNotEmpty()) {
            listState.animateScrollToItem(filtered.lastIndex)
        }
    }
}
