package com.eltavine.duckdetector.features.settings.ui.components

import android.content.ClipData
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Email
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.ui.theme.ShapeTokens

private const val ABOUT_WEBSITE = "eltavine.com"
private const val ABOUT_EMAIL = "me@eltavine.com"

@Composable
fun AboutCard(
    versionName: String,
    versionCode: Int,
    buildTimeUtc: String,
    buildHash: String,
    modifier: Modifier = Modifier,
) {
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    shape = ShapeTokens.CornerLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                ) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .padding(10.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Info,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }

                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    WrapSafeText(
                        text = "About",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = "Project links and build metadata.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                AboutInfoRow(
                    label = "Version",
                    value = "$versionName ($versionCode)",
                    icon = Icons.Rounded.Badge,
                )
                AboutInfoRow(
                    label = "Website",
                    value = ABOUT_WEBSITE,
                    icon = Icons.Rounded.Language,
                    onClick = { uriHandler.openUri("https://$ABOUT_WEBSITE") },
                )
                AboutInfoRow(
                    label = "Email",
                    value = ABOUT_EMAIL,
                    icon = Icons.Rounded.Email,
                    onClick = { uriHandler.openUri("mailto:$ABOUT_EMAIL") },
                )
                AboutInfoRow(
                    label = "Build Time",
                    value = "${formatBuildTimeUtc(buildTimeUtc)} UTC",
                    icon = Icons.Rounded.Schedule,
                )
                AboutInfoRow(
                    label = "Build Hash",
                    value = buildHash,
                    icon = Icons.Rounded.Badge,
                )
                AboutInfoRow(
                    label = "Privacy / Data Use",
                    value = "Checks run locally on-device. Online CRL lookup is optional and only happens if you enable it in Settings.",
                    icon = Icons.Rounded.Info,
                )
                AboutInfoRow(
                    label = "Copy Build Info",
                    value = "Copy version, build time and build hash",
                    icon = Icons.Rounded.ContentCopy,
                    onClick = {
                        val clipboard =
                            context.getSystemService(android.content.ClipboardManager::class.java)
                        clipboard?.setPrimaryClip(
                            ClipData.newPlainText(
                                "Duck Detector build info",
                                buildClipboardText(
                                    versionName = versionName,
                                    versionCode = versionCode,
                                    buildTimeUtc = buildTimeUtc,
                                    buildHash = buildHash,
                                ),
                            ),
                        )
                        Toast.makeText(context, "Build info copied", Toast.LENGTH_SHORT).show()
                    },
                )
            }
        }
    }
}

private fun buildClipboardText(
    versionName: String,
    versionCode: Int,
    buildTimeUtc: String,
    buildHash: String,
): String {
    return buildString {
        append("Version: ")
        append(versionName)
        append(" (")
        append(versionCode)
        append(')')
        append('\n')
        append("Build Time (UTC): ")
        append(formatBuildTimeUtc(buildTimeUtc))
        append(" UTC")
        append('\n')
        append("Build Hash: ")
        append(buildHash)
    }
}

@Composable
private fun AboutInfoRow(
    label: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: (() -> Unit)? = null,
) {
    Surface(
        shape = ShapeTokens.CornerLarge,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = onClick != null) {
                    onClick?.invoke()
                }
                .padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                WrapSafeText(
                    text = label,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                WrapSafeText(
                    text = value,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}
