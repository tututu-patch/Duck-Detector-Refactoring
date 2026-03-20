package com.eltavine.duckdetector.ui.shell

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CloudSync
import androidx.compose.material.icons.rounded.Inventory2
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Update
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.ui.theme.ShapeTokens

data class StartupPackageVisibilityState(
    val visibility: InstalledPackageVisibility,
    val visiblePackageCount: Int,
    val suspiciouslyLowInventory: Boolean,
)

@Composable
fun StartupPolicyScreen(
    gateState: StartupGateState,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    teePrefs: TeeNetworkPrefs?,
    packageVisibilityState: StartupPackageVisibilityState?,
    packageVisibilityReviewAcknowledged: Boolean,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
    onAllowCrlNetwork: () -> Unit,
    onUseLocalCrlOnly: () -> Unit,
    onAcknowledgePackageVisibility: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cards = if (
        gateState == StartupGateState.LOADING ||
        notificationPrefs == null ||
        teePrefs == null ||
        packageVisibilityState == null
    ) {
        emptyList()
    } else {
        buildList {
            add(
                notificationPolicyCard(
                    notificationPrefs = notificationPrefs,
                    permissionState = notificationPermissionState,
                    onAllowNotifications = onAllowNotifications,
                    onSkipNotifications = onSkipNotifications,
                ),
            )
            add(
                liveUpdatePolicyCard(
                    notificationPrefs = notificationPrefs,
                    permissionState = notificationPermissionState,
                    onOpenLiveUpdateSettings = onOpenLiveUpdateSettings,
                    onUseRegularNotifications = onUseRegularNotifications,
                ),
            )
            add(
                crlPolicyCard(
                    teePrefs = teePrefs,
                    onAllowCrlNetwork = onAllowCrlNetwork,
                    onUseLocalCrlOnly = onUseLocalCrlOnly,
                ),
            )
            add(
                packageManagerPolicyCard(
                    packageVisibilityState = packageVisibilityState,
                    packageVisibilityReviewAcknowledged = packageVisibilityReviewAcknowledged,
                    onAcknowledgePackageVisibility = onAcknowledgePackageVisibility,
                ),
            )
        }
    }
    val resolvedCount = cards.count { !it.requiresAction }
    val totalCount = cards.size.coerceAtLeast(1)
    val progress = resolvedCount.toFloat() / totalCount.toFloat()

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StartupPolicyHero(
                gateState = gateState,
                resolvedCount = resolvedCount,
                totalCount = totalCount,
                progress = progress,
            )

            if (gateState == StartupGateState.LOADING) {
                LoadingPolicyCard()
            } else {
                cards.forEach { card ->
                    StartupPolicyCard(card = card)
                }
            }
        }
    }
}

@Composable
private fun StartupPolicyHero(
    gateState: StartupGateState,
    resolvedCount: Int,
    totalCount: Int,
    progress: Float,
) {
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(60.dp)
                        .background(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerifiedUser,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.size(28.dp),
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    WrapSafeText(
                        text = "Startup policy review",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    WrapSafeText(
                        text = if (gateState == StartupGateState.LOADING) {
                            "Preparing startup"
                        } else {
                            "Before the scan"
                        },
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    "Preferences and PackageManager visibility are still being loaded. Detector ViewModels stay paused until this completes."
                } else {
                    "Finish the required choices before detector scans begin. Notifications, Live Update routing, CRL networking, and PackageManager visibility are reviewed here in one place. The detector pipeline remains blocked until every required card below is settled."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
            )

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    "Loading startup state..."
                } else {
                    "$resolvedCount of $totalCount startup cards resolved"
                },
                style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Medium),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LoadingPolicyCard() {
    Surface(
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(28.dp),
                strokeWidth = 3.dp,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                WrapSafeText(
                    text = "Loading startup dependencies",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = "Reading consent stores and PackageManager visibility before any detector starts.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StartupPolicyCard(
    card: StartupPolicyCardUi,
) {
    val colors = card.tone.colors()
    Surface(
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
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(color = colors.container, shape = ShapeTokens.CornerLarge),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = card.icon,
                        contentDescription = null,
                        tint = colors.content,
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        WrapSafeText(
                            text = card.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        StatusBadge(
                            label = card.statusLabel,
                            containerColor = colors.container,
                            contentColor = colors.content,
                        )
                    }

                    WrapSafeText(
                        text = card.headline,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = card.detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (card.primaryActionLabel != null || card.secondaryActionLabel != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (card.secondaryActionLabel != null && card.onSecondaryAction != null) {
                        OutlinedButton(onClick = card.onSecondaryAction) {
                            WrapSafeText(
                                text = card.secondaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                    }

                    if (card.primaryActionLabel != null && card.onPrimaryAction != null) {
                        FilledTonalButton(onClick = card.onPrimaryAction) {
                            WrapSafeText(
                                text = card.primaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(
    label: String,
    containerColor: Color,
    contentColor: Color,
) {
    Surface(
        color = containerColor,
        shape = ShapeTokens.CornerFull,
    ) {
        WrapSafeText(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = contentColor,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
        )
    }
}

private fun notificationPolicyCard(
    notificationPrefs: ScanNotificationPrefs,
    permissionState: ScanNotificationPermissionState,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
): StartupPolicyCardUi {
    return when {
        permissionState.notificationsGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = "Notifications",
            statusLabel = "Ready",
            headline = "Scan notifications are enabled.",
            detail = "Duck Detector can publish scan-progress notifications while detector cards collect evidence.",
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )

        !notificationPrefs.notificationsPrompted -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = "Notifications",
            statusLabel = "Action required",
            headline = "Choose whether scan progress may post notifications.",
            detail = if (Build.VERSION.SDK_INT >= 33) {
                "Android ${Build.VERSION.SDK_INT} requires runtime notification permission. Startup scanning stays blocked until you allow it or explicitly continue without it."
            } else {
                "This Android version does not require a runtime notification prompt, but the startup policy still needs to record your choice."
            },
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = "Allow notifications",
            secondaryActionLabel = "Skip",
            onPrimaryAction = onAllowNotifications,
            onSecondaryAction = onSkipNotifications,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = "Notifications",
            statusLabel = "Skipped",
            headline = "Notifications were skipped.",
            detail = "Scan progress will stay inside the app until you grant notification permission later.",
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

private fun liveUpdatePolicyCard(
    notificationPrefs: ScanNotificationPrefs,
    permissionState: ScanNotificationPermissionState,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
): StartupPolicyCardUi {
    return when {
        !permissionState.liveUpdatesSupported -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = "Live Update",
            statusLabel = "Unsupported",
            headline = "Promoted ongoing notifications are not available on this Android version.",
            detail = "Duck Detector will use a regular notification path when notification permission is available.",
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        !permissionState.notificationsGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = "Live Update",
            statusLabel = "Waiting",
            headline = "Live Update depends on the notification path.",
            detail = "Grant notification permission first. If you keep notifications disabled, this card will fall back to regular in-app progress only.",
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        permissionState.liveUpdatesGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = "Live Update",
            statusLabel = "Ready",
            headline = "Promoted ongoing notifications are allowed.",
            detail = "On supported Android versions, scan progress can surface through the richer Live Update path.",
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )

        !notificationPrefs.liveUpdatesPrompted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = "Live Update",
            statusLabel = "Action required",
            headline = "Choose whether to use the Android Live Update path.",
            detail = "Duck Detector can open the system page for promoted ongoing notifications. If you skip this, scan progress falls back to a regular notification.",
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = "Open settings",
            secondaryActionLabel = "Use regular",
            onPrimaryAction = onOpenLiveUpdateSettings,
            onSecondaryAction = onUseRegularNotifications,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = "Live Update",
            statusLabel = "Regular",
            headline = "Regular notifications were selected.",
            detail = "Promoted ongoing notifications stay disabled. Scan progress will use the regular notification path instead.",
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

private fun crlPolicyCard(
    teePrefs: TeeNetworkPrefs,
    onAllowCrlNetwork: () -> Unit,
    onUseLocalCrlOnly: () -> Unit,
): StartupPolicyCardUi {
    return if (!teePrefs.consentAsked) {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = "CRL networking",
            statusLabel = "Action required",
            headline = "Choose whether TEE revocation checks may use the network.",
            detail = "Allowing network lets Duck Detector query Google's attestation revocation feed during TEE validation. Local-only mode skips online refresh.",
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = "Allow network",
            secondaryActionLabel = "Local only",
            onPrimaryAction = onAllowCrlNetwork,
            onSecondaryAction = onUseLocalCrlOnly,
        )
    } else if (teePrefs.consentGranted) {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = "CRL networking",
            statusLabel = "Ready",
            headline = "Online CRL refresh is allowed.",
            detail = "TEE validation may refresh Google's attestation revocation feed whenever network conditions permit.",
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )
    } else {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = "CRL networking",
            statusLabel = "Local",
            headline = "TEE revocation checks are local-only.",
            detail = "Duck Detector will not perform online CRL refresh until you re-enable it in Settings.",
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

private fun packageManagerPolicyCard(
    packageVisibilityState: StartupPackageVisibilityState,
    packageVisibilityReviewAcknowledged: Boolean,
    onAcknowledgePackageVisibility: () -> Unit,
): StartupPolicyCardUi {
    return when {
        packageVisibilityState.visibility == InstalledPackageVisibility.RESTRICTED &&
                !packageVisibilityReviewAcknowledged -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = "PackageManager",
            statusLabel = "Action required",
            headline = "Package inventory looks scoped or filtered.",
            detail = "PackageManager exposed only ${packageVisibilityState.visiblePackageCount} installed packages. Dangerous Apps and related probes can under-report installed tools under restricted visibility, scoped inventory, or HMA-style filtering.",
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = "Continue anyway",
            onPrimaryAction = onAcknowledgePackageVisibility,
        )

        packageVisibilityState.visibility == InstalledPackageVisibility.RESTRICTED -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = "PackageManager",
            statusLabel = "Acknowledged",
            headline = "Restricted PackageManager visibility was acknowledged.",
            detail = "Current visible package count: ${packageVisibilityState.visiblePackageCount}. Dangerous Apps findings may be conservative under this inventory scope.",
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )

        packageVisibilityState.suspiciouslyLowInventory -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = "PackageManager",
            statusLabel = "Review later",
            headline = "PackageManager looks full but the visible inventory is unusually small.",
            detail = "Current visible package count: ${packageVisibilityState.visiblePackageCount}. Startup will continue, but Dangerous Apps will review this low-inventory condition as potential filtering evidence.",
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = "PackageManager",
            statusLabel = "Ready",
            headline = "PackageManager inventory looks full.",
            detail = "Current visible package count: ${packageVisibilityState.visiblePackageCount}. Dangerous Apps can use the standard package inventory path.",
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )
    }
}

private data class StartupPolicyCardUi(
    val icon: ImageVector,
    val title: String,
    val statusLabel: String,
    val headline: String,
    val detail: String,
    val tone: StartupPolicyTone,
    val requiresAction: Boolean,
    val primaryActionLabel: String? = null,
    val secondaryActionLabel: String? = null,
    val onPrimaryAction: (() -> Unit)? = null,
    val onSecondaryAction: (() -> Unit)? = null,
)

private enum class StartupPolicyTone {
    REQUIRED,
    READY,
    ACKNOWLEDGED,
    SUPPORT,
}

private data class StartupPolicyColors(
    val container: Color,
    val content: Color,
)

private fun StartupPolicyTone.colors(): StartupPolicyColors {
    return when (this) {
        StartupPolicyTone.REQUIRED -> StartupPolicyColors(
            container = Color(0xFFFDE7D9),
            content = Color(0xFF9A3412),
        )

        StartupPolicyTone.READY -> StartupPolicyColors(
            container = Color(0xFFDDF4E4),
            content = Color(0xFF166534),
        )

        StartupPolicyTone.ACKNOWLEDGED -> StartupPolicyColors(
            container = Color(0xFFE8ECF8),
            content = Color(0xFF334155),
        )

        StartupPolicyTone.SUPPORT -> StartupPolicyColors(
            container = Color(0xFFE9E7FF),
            content = Color(0xFF5B43B5),
        )
    }
}
