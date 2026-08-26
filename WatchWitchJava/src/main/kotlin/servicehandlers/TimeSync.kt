package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPDict
import net.rec0de.android.watchwitch.decoders.bplist.BPListObject
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.NSDict

object TimeSync : AlloyService {

    override val handlesTopics = listOf("com.apple.private.alloy.timesync")
    private const val TAG = "TimeSync"

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is DataMessage)
            throw Exception("TimeSync expects DataMessage but got $msg")

        val parsed = BPListParser().parse(msg.payload)
        val message: NSDict = when (parsed) {
            is BPDict -> NSDict(parsed.values as Map<BPListObject, BPListObject>)
            is NSDict -> parsed
            else -> {
                Log.d(TAG, "unexpected BPList data: $parsed")
                return
            }
        }

        Log.d(TAG, "got message $message")
        if(message.values.containsKey(BPAsciiString("kTMLSLinkTimeZoneKey"))) {
            val timezone = message.values[BPAsciiString("kTMLSLinkTimeZoneKey")] as BPAsciiString
            WatchState.addStolenInfo("Timezone: ${timezone.value}")
        }
    }
}