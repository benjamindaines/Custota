/*
 * SPDX-FileCopyrightText: 2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import com.chiller3.custota.Notifications
import com.chiller3.custota.Preferences
import com.chiller3.custota.R
import com.chiller3.custota.ui.MdBullet
import com.chiller3.custota.ui.MdBlock
import com.chiller3.custota.ui.MdCodeBlock
import com.chiller3.custota.ui.MdDivider
import com.chiller3.custota.ui.MdHeading
import com.chiller3.custota.ui.MdNumbered
import com.chiller3.custota.ui.MdParagraph
import com.chiller3.custota.ui.MdSpan
import com.chiller3.custota.ui.Markdown
import com.chiller3.custota.ui.theme.AppTheme
import com.chiller3.custota.updater.PackageConflictResolver
import android.os.Process
import android.util.Log

/**
 * Full-screen activity shown when the user taps "Install" on the update-available notification and
 * the OTA has an associated message (a `<device>.md` file alongside the `<device>.json`). The
 * message is rendered (Markdown), and the user must scroll to the bottom to reach the
 * "Install" / "Don't Install" buttons. Choosing "Install" proceeds with the actual installation.
 */
class UpdateMessageActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val message = intent.getStringExtra(EXTRA_MESSAGE).orEmpty()
        val fingerprints = intent.getStringArrayListExtra(EXTRA_FINGERPRINTS) ?: arrayListOf()

        setContent {
            AppTheme {
                UpdateMessageScreen(
                    message = message,
                    fingerprints = fingerprints,
                    onInstall = {
                        confirmInstall()
                        finish()
                    },
                    onCancel = { finish() },
                    onOpenWebsite = { openWebsite() },
                    onOpenKofi = { openKofi() },
                )
            }
        }
    }

    private fun confirmInstall() {
        Notifications(this).dismissAlert()
       /* val appContext = applicationContext
        Thread {
            val removed = PackageConflictResolver(appContext).resolveConflicts()
            Log.i("UpdateMessageActivity", "DEBUG conflict resolution removed: $removed")
        }.start() */
        UpdaterJob.scheduleImmediate(this, UpdaterThread.Action.INSTALL_CONFIRMED) 
    }

    /** Open the configured BenOS website URL in the user's browser. */
    private fun openWebsite() {
        val url = Preferences(this).benosWebsiteUrl
        try {
            val intent = Intent(Intent.ACTION_VIEW, url.toUri())
            startActivity(intent)
        } catch (e: Exception) {
            Log.w("UpdateMessageActivity", "Failed to open website: $url", e)
        }
    }
    
    private fun openKofi() {
        val url = Preferences(this).benosKofiUrl
        try {
            val intent = Intent(Intent.ACTION_VIEW, url.toUri())
            startActivity(intent)
        } catch (e: Exception) {
            Log.w("UpdateMessageActivity", "Failed to open website: $url", e)
        }
    }


    companion object {
        private const val EXTRA_MESSAGE = "message"
        private const val EXTRA_FINGERPRINTS = "fingerprints"

        fun createIntent(
            context: Context,
            message: String,
            fingerprints: List<String>,
        ) = Intent(context, UpdateMessageActivity::class.java).apply {
            putExtra(EXTRA_MESSAGE, message)
            putStringArrayListExtra(EXTRA_FINGERPRINTS, ArrayList(fingerprints))
        }
    }
}

@Composable
private fun UpdateMessageScreen(
    message: String,
    fingerprints: List<String>,
    onInstall: () -> Unit,
    onCancel: () -> Unit,
    onOpenWebsite: () -> Unit,
    onOpenKofi: () -> Unit,
) {
    val blocks = remember(message) { Markdown.parse(message) }
    val insets = WindowInsets.systemBars.asPaddingValues()

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(insets)
                .padding(horizontal = 24.dp, vertical = 16.dp),
        ) {
            Text(
                text = stringResource(R.string.update_message_title),
                style = MaterialTheme.typography.headlineSmall,
            )

            if (fingerprints.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = fingerprints.joinToString("\n"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(16.dp))

            MarkdownContent(blocks)

            Spacer(Modifier.height(32.dp))

            // Bottom action bar, sized for a 720x720 screen: the "Open BenOS
            // Website" button sits on the left, and the existing actions stay on
            // the right, pushed over by a flexible spacer.
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
		Button(onClick = onOpenKofi, 
		    colors = ButtonDefaults.buttonColors(
		       // containerColor = Color(0xFF168553),
		        containerColor = Color(0xFFa4edb2),
		        contentColor = Color(0xFF573f45)
		 	) 
		    ) {
                    Text(stringResource(R.string.update_message_open_kofi))
                }
                Spacer(Modifier.weight(1f)) 
                OutlinedButton(onClick = onOpenWebsite) {
                    Text(stringResource(R.string.update_message_open_website))
                }
                Spacer(Modifier.weight(1f))
                OutlinedButton(onClick = onCancel) {
                    Text(stringResource(R.string.update_message_dont_install))
                }
                Spacer(Modifier.width(12.dp))
                Button(onClick = onInstall) {
                    Text(stringResource(R.string.notification_action_install))
                }
            }
        }
    }
}

@Composable
private fun MarkdownContent(blocks: List<MdBlock>) {
    Column(modifier = Modifier.fillMaxWidth()) {
        for (block in blocks) {
            when (block) {
                is MdHeading -> {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = annotated(block.spans),
                        style = when (block.level) {
                            1 -> MaterialTheme.typography.titleLarge
                            2 -> MaterialTheme.typography.titleMedium
                            else -> MaterialTheme.typography.titleSmall
                        },
                    )
                    Spacer(Modifier.height(4.dp))
                }
                is MdParagraph -> {
                    Text(
                        text = annotated(block.spans),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 4.dp),
                    )
                }
                is MdBullet -> {
                    Row(modifier = Modifier.padding(vertical = 2.dp)) {
                        Text("•  ", style = MaterialTheme.typography.bodyMedium)
                        Text(annotated(block.spans), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                is MdNumbered -> {
                    Row(modifier = Modifier.padding(vertical = 2.dp)) {
                        Text("${block.number}.  ", style = MaterialTheme.typography.bodyMedium)
                        Text(annotated(block.spans), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                is MdCodeBlock -> {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp),
                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                        shape = MaterialTheme.shapes.small,
                    ) {
                        Text(
                            text = block.text,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(12.dp),
                        )
                    }
                }
                MdDivider -> {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                }
            }
        }
    }
}

@Composable
private fun annotated(spans: List<MdSpan>): AnnotatedString {
    val linkColor = MaterialTheme.colorScheme.primary
    return buildAnnotatedString {
        for (s in spans) {
            val style = SpanStyle(
                fontWeight = if (s.bold) FontWeight.Bold else null,
                fontStyle = if (s.italic) FontStyle.Italic else null,
                fontFamily = if (s.code) FontFamily.Monospace else null,
                textDecoration = if (s.link != null) TextDecoration.Underline else null,
                color = if (s.link != null) linkColor else Color.Unspecified,
            )
            val link = s.link
            if (link != null) {
                // Wrap the text in a real URL link annotation so that tapping it
                // opens the browser. Styling-only spans (the previous behavior)
                // looked like links but did not fire any intent.
                withLink(LinkAnnotation.Url(link, TextLinkStyles(style = style))) {
                    append(s.text)
                }
            } else {
                withStyle(style) {
                    append(s.text)
                }
            }
        }
    }
}
