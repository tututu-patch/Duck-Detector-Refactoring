package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs

enum class AppDestination {
    MAIN,
    SETTINGS,
}

enum class StartupGateState {
    LOADING,
    REQUIRES_POLICY_REVIEW,
    READY,
}

fun resolveStartupGateState(
    teePrefs: TeeNetworkPrefs?,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    packageVisibilityLoaded: Boolean,
    packageVisibility: InstalledPackageVisibility,
    packageVisibilityReviewAcknowledged: Boolean,
): StartupGateState {
    return when {
        teePrefs == null || notificationPrefs == null || !packageVisibilityLoaded ->
            StartupGateState.LOADING

        !notificationPrefs.notificationsPrompted &&
                !notificationPermissionState.notificationsGranted ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        notificationPermissionState.notificationsGranted &&
                notificationPermissionState.liveUpdatesSupported &&
                !notificationPermissionState.liveUpdatesGranted &&
                !notificationPrefs.liveUpdatesPrompted ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        !teePrefs.consentAsked -> StartupGateState.REQUIRES_POLICY_REVIEW
        packageVisibility == InstalledPackageVisibility.RESTRICTED &&
                !packageVisibilityReviewAcknowledged ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        else -> StartupGateState.READY
    }
}

fun shouldCreateDetectorViewModels(gateState: StartupGateState): Boolean {
    return gateState == StartupGateState.READY
}
