package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPInt
import net.rec0de.android.watchwitch.decoders.bplist.BPListObject
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.NSArray
import net.rec0de.android.watchwitch.decoders.bplist.NSDict

object CoreDuet : AlloyService {

    override val handlesTopics = listOf("com.apple.private.alloy.coreduet")

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = true

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is DataMessage)
            throw Exception("CoreDuet expects DataMessage but got $msg")

        val parsed = BPListParser().parse(msg.payload)
        val messages: List<NSDict> = when {
            parsed is NSDict -> listOf(parsed)
            parsed is NSArray -> parsed.values.map { it as NSDict }
            else -> throw Exception("unexpected BPList data: $parsed")
        }

        println(messages.map { CoreDuetMessage.fromNSDict(it) })
    }

    class CoreDuetMessage(val version: Int, val type: Int, val maxVersion: Int, val minVersion: Int, val payload: BPListObject?) {
        companion object {
            private val types = listOf("SYSTEM_DATA", "ADMISSION_DATA", "FORECAST_DATA", "STATISTIC_DATA", "DATA_VALUE_REQUEST", "ACK", "SYNC_REQUEST")

            fun fromNSDict(dict: NSDict): CoreDuetMessage {
                val type = (dict.values[BPInt(0)] as BPInt).value.toInt()
                val version = (dict.values[BPInt(1)] as BPInt).value.toInt()
                val payload = dict.values[BPInt(2)]
                val minmax = (dict.values[BPInt(4)] as NSDict).values

                val minVersion = (minmax[BPAsciiString("MinVersion")] as BPInt).value.toInt()
                val maxVersion = (minmax[BPAsciiString("MaxVersion")] as BPInt).value.toInt()

                return CoreDuetMessage(version, type, maxVersion, minVersion, dict)
            }
        }

        override fun toString(): String {
            return "CDMsg(v$version ($minVersion/$maxVersion), type ${types[type]}($type), $payload)"
        }
    }
}