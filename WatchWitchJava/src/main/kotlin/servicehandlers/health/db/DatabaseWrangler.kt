package net.rec0de.android.watchwitch.servicehandlers.health.db

import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.Utils
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.servicehandlers.health.ActivityCache
import net.rec0de.android.watchwitch.servicehandlers.health.BinarySample
import net.rec0de.android.watchwitch.servicehandlers.health.ECGSample
import net.rec0de.android.watchwitch.servicehandlers.health.HealthObject
import net.rec0de.android.watchwitch.servicehandlers.health.LocationSeries
import net.rec0de.android.watchwitch.servicehandlers.health.Provenance
import net.rec0de.android.watchwitch.servicehandlers.health.QuantitySample
import net.rec0de.android.watchwitch.servicehandlers.health.Sample
import net.rec0de.android.watchwitch.servicehandlers.health.Source
import net.rec0de.android.watchwitch.servicehandlers.health.SyncStatusKey
import net.rec0de.android.watchwitch.servicehandlers.health.TimestampedKeyValuePair
import net.rec0de.android.watchwitch.servicehandlers.health.Workout
import java.util.UUID


object DatabaseWrangler {

    fun insertCategorySample(value: Int, provenanceId: Int, sample: Sample) {
        Logger.logSQL("Inserting category sample: $sample value: $value", 0)
    }

    fun insertBinarySample(sample: BinarySample, provenanceId: Int) {
        Logger.logSQL("Inserting binary sample: $sample payload: ${sample.payload.hex()}", 0)
    }

    fun insertEcgSample(sample: ECGSample, provenanceId: Int) {
        Logger.logSQL("Inserting ECG sample: $sample", 0)
    }

    fun insertWorkout(sample: Workout, provenanceId: Int) {
        Logger.logSQL("Inserting workout: $sample", 0)
    }

    fun insertActivityCache(ac: ActivityCache, provenanceId: Int) {
        Logger.logSQL("Inserting activity cache: $ac", 0)
    }

    fun insertLocationSeries(sample: LocationSeries, provenanceId: Int) {
        Logger.logSQL("got LocationSeries: $sample", 0)
    }

    fun insertQuantitySample(sample: QuantitySample, provenanceId: Int) {

    }

    private fun insertSample(id: Int, sample: Sample) {
        Logger.logSQL("Inserting sample: $sample", 1)
    }

    private fun insertObject(obj: HealthObject, provenanceId: Int): Int {
        Logger.logSQL("Inserting health object: $obj", 2)
        return 0
    }

    fun getOrInsertProvenance(provenance: Provenance, source: Source?): Int {
        return 0
    }

    private fun insertProvenance(provenance: Provenance, sourceId: Int?) {
        Logger.logSQL("Inserting provenance: $provenance", 2)
    }

    private fun insertSourceIfNotPresent(source: Source): Int {
        return 0
    }

    private fun insertSource(source: Source): Int {
        return 0
    }

    private fun getOrInsertUnitString(unit: String): Int {
        return 0
    }

    private fun getOrInsertMetadataKey(key: String): Int {
        return 0
    }

    fun setKeyValueSecure(domain: String?, category: Int, kvp: TimestampedKeyValuePair) {
        Logger.logSQL("Inserted KeyValueSecure: $domain-$category: $kvp", 0)
    }

    fun setKeyValue(domain: String?, category: Int, kvp: TimestampedKeyValuePair) {
        Logger.logSQL("Inserted KeyValue: $domain-$category: $kvp", 0)
    }

    fun markSampleDeleted(uuid: UUID) {
        Logger.logSQL("Marking sample with uuid $uuid as deleted", 0)
    }

    fun setSyncAnchor(schema: String, objType: Int, identifier: Int, value: Int, remote: Boolean) {
        Logger.logSQL("Set SyncAnchor: $schema-$objType-$identifier: $value", 2)
    }

    fun resetSyncStatus() {}

    fun loadSyncAnchors(): Map<SyncStatusKey,Int> {
        return emptyMap()
    }

}