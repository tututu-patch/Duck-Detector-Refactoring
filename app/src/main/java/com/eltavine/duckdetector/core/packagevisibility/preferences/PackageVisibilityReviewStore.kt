package com.eltavine.duckdetector.core.packagevisibility.preferences

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStoreFile
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

data class PackageVisibilityReviewPrefs(
    val restrictedInventoryAcknowledged: Boolean,
)

class PackageVisibilityReviewStore private constructor(
    context: Context,
) {
    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("package_visibility_review_prefs") },
    )

    val prefs: Flow<PackageVisibilityReviewPrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            PackageVisibilityReviewPrefs(
                restrictedInventoryAcknowledged =
                    prefs[KEY_RESTRICTED_INVENTORY_ACKNOWLEDGED] ?: false,
            )
        }

    suspend fun acknowledgeRestrictedInventory() {
        dataStore.edit { prefs ->
            prefs[KEY_RESTRICTED_INVENTORY_ACKNOWLEDGED] = true
        }
    }

    companion object {
        @Volatile
        private var instance: PackageVisibilityReviewStore? = null

        private val KEY_RESTRICTED_INVENTORY_ACKNOWLEDGED =
            booleanPreferencesKey("restricted_inventory_acknowledged")

        fun getInstance(context: Context): PackageVisibilityReviewStore {
            return instance ?: synchronized(this) {
                instance
                    ?: PackageVisibilityReviewStore(context.applicationContext).also { created ->
                        instance = created
                    }
            }
        }
    }
}
