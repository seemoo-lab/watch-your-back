package net.rec0de.android.watchwitch

import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.Volatile

/*
 * A place to gather information about the current state of the connected watch, mostly sourced from NanoPreferencesSync
 */
object WatchState {

    @Volatile
    var networkPlumbingDone = AtomicBoolean(false)
    @Volatile
    var alloyConnected = AtomicBoolean(false)
    @Volatile
    var wifiRequested = AtomicBoolean(false)

    val stolenInfo = mutableSetOf<String>()
    private var pairingProgress = 0
    private val demopath = "file:///home/user/Documents/WatchWitch/WatchWitchJava/build/libs"

    fun resetConnectionState() {
        alloyConnected.set(false)
        networkPlumbingDone.set(false)
    }

    fun setBtPin(pin: String) {
        Log.big("WatchState", "Bluetooth PIN: $pin")
    }

    fun setPairingStage(stage: String) {
        Log.big("WatchState", stage)

    }

    @Synchronized
    fun incrementProgress() {
        pairingProgress += 1
        //Log.d("WatchState", "new pairing progress: $pairingProgress")
    }

    @Synchronized
    fun addStolenInfo(info: String) {
        stolenInfo.add(info)
        Log.big("StolenInfo", info)
    }

    @Synchronized
    fun addStolenInfo(info: Set<String>) {
        stolenInfo.addAll(info)
        info.forEach {
            Log.big("StolenInfo", it)
        }
    }

    fun renderStolenInfo(): String {
        return stolenInfo.joinToString("\n") {
            if(it.startsWith("img"))
                "<div><img src=\"$demopath/$it\"></div>"
            else
                "<div>$it</div>"
        }
    }
}