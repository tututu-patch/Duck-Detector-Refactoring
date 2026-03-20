package com.eltavine.duckdetector.core.startup.legal

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

data class AgreementAcceptancePrefs(
    val accepted: Boolean,
)

class AgreementAcceptanceStore private constructor(
    context: Context,
) {
    private val dataStore = PreferenceDataStoreFactory.create(
        produceFile = { context.preferencesDataStoreFile("startup_agreement_prefs") },
    )

    val prefs: Flow<AgreementAcceptancePrefs> = dataStore.data
        .catch { throwable ->
            if (throwable is IOException) {
                emit(emptyPreferences())
            } else {
                throw throwable
            }
        }
        .map { prefs ->
            AgreementAcceptancePrefs(
                accepted = prefs[KEY_ACCEPTED] ?: false,
            )
        }

    suspend fun accept() {
        dataStore.edit { prefs ->
            prefs[KEY_ACCEPTED] = true
        }
    }

    companion object {
        @Volatile
        private var instance: AgreementAcceptanceStore? = null

        private val KEY_ACCEPTED = booleanPreferencesKey("accepted")

        fun getInstance(context: Context): AgreementAcceptanceStore {
            return instance ?: synchronized(this) {
                instance ?: AgreementAcceptanceStore(context.applicationContext).also { created ->
                    instance = created
                }
            }
        }
    }
}
