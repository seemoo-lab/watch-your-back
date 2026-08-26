package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.alloy.ProtobufMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPDict
import net.rec0de.android.watchwitch.decoders.bplist.BPFalse
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.BPSDict
import net.rec0de.android.watchwitch.decoders.protobuf.ProtobufParser
import java.util.UUID

object Baseband : AlloyService {

    private const val P2W = "com.apple.private.alloy.ct.commcenter.p2w.settings"
    private const val P2P = "com.apple.private.alloy.ct.baseband.p2p.notification"
    private const val SIM = "com.apple.private.alloy.ct.commcenter.sim"
    override val handlesTopics = listOf(P2P, P2W, SIM)
    private const val TAG = "Baseband/CT"

    override fun acceptsMessageType(msg: AlloyMessage) = true
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg is ProtobufMessage && msg.topic == SIM){
            val parsed = if(BPListParser.bufferIsBPList(msg.payload)) BPListParser().parse(msg.payload).toString() else ProtobufParser().parse(msg.payload).toString()
            Log.d(TAG, "got message type ${msg.type}: $parsed")
            return
        }

        if(msg !is DataMessage)
            throw Exception("$TAG expects DataMessage but got $msg")

        val parsed = BPListParser().parse(msg.payload)
        Log.d(TAG, "got message: $parsed")

        when(msg.topic) {
            P2W -> {
                //Log.d(TAG, "replying with IAM")
                //send(genIAM().renderAsTopLevelObject(), P2W, handler)
            }
            P2P -> {
                //Log.d(TAG, "replying with IAM")
                //send(genIAM().renderAsTopLevelObject(), P2P, handler)
            }

        }
    }

    private fun genIAM() = BPSDict(mapOf(
        "control" to BPSDict(mapOf(
            "devinfo" to BPDict(emptyMap()),
            "type" to BPAsciiString("I am"),
            "capable" to BPFalse
        ))
    ))

    private fun send(data: ByteArray, topic: String, handler: AlloyHandler) {
        handler.sendData(data, topic, UUID.randomUUID())
    }
}