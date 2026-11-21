package dev.yazwa.nyampy

import android.content.Context
import androidx.room.Room
import dev.yazwa.nyampy.data.SettingsStore
import dev.yazwa.nyampy.db.NyampyDatabase
import dev.yazwa.nyampy.sub.HappSpoof
import dev.yazwa.nyampy.sub.HappSpoof.happFingerprint
import dev.yazwa.nyampy.sub.SubscriptionRepository

/**
 * The main process's few long-lived objects: the Room database and the subscription
 * repository on top of it. The ":core" process never touches this — it receives the
 * rendered mihomo document through the file hand-off instead.
 */
object Graph {
    lateinit var database: NyampyDatabase
        private set

    lateinit var subscriptions: SubscriptionRepository
        private set

    fun init(context: Context) {
        if (::database.isInitialized) return
        val application = context.applicationContext
        database = Room.databaseBuilder(
            application,
            NyampyDatabase::class.java,
            NyampyDatabase.NAME,
        ).addMigrations(
            NyampyDatabase.MIGRATION_1_2,
            NyampyDatabase.MIGRATION_2_3,
            NyampyDatabase.MIGRATION_3_4,
            NyampyDatabase.MIGRATION_4_5,
            NyampyDatabase.MIGRATION_5_6,
            NyampyDatabase.MIGRATION_6_7,
            NyampyDatabase.MIGRATION_7_8,
            NyampyDatabase.MIGRATION_8_9,
            NyampyDatabase.MIGRATION_9_10,
            NyampyDatabase.MIGRATION_10_11,
            NyampyDatabase.MIGRATION_11_12,
            NyampyDatabase.MIGRATION_12_13,
            NyampyDatabase.MIGRATION_13_14,
            NyampyDatabase.MIGRATION_14_15,
            NyampyDatabase.MIGRATION_15_16,
        ).build()
        subscriptions = SubscriptionRepository(
            context = application,
            db = database,
            // Read at fetch time, through the shared settings state: the Happ
            // fingerprint follows the toggle the moment it flips, and every fetch -
            // manual or background, first hop or nested — dresses up the same way.
            happSpoof = {
                SettingsStore.settings(application).value.happFingerprint()
            },
        )
    }
}
