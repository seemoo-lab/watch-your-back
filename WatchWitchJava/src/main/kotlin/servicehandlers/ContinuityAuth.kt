package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.ProtobufMessage
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoBuf
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoLen
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoString
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoVarInt
import net.rec0de.android.watchwitch.decoders.protobuf.ProtobufParser
import java.util.UUID

object ContinuityAuth : AlloyService {

    private const val TOPIC = "com.apple.private.alloy.continuity.auth"
    override val handlesTopics = listOf(TOPIC)
    private const val TAG = "ContinuityAuth"

    override fun acceptsMessageType(msg: AlloyMessage) = msg is ProtobufMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is ProtobufMessage)
            throw Exception("$TAG expects ProtobufMessage but got $msg")

        val parsed = ProtobufParser().parse(msg.payload)
        Log.d(TAG, "got message type ${msg.type}: $parsed")

        when(msg.type) {
            107 -> {
                // pubkeys?
                Log.d(TAG, "is response pubkeys, nothing to do")
            }
            108 -> {
                // request for pubkeys?
                // using static public keys for now, i don't think we actually need them
                val asn1 = "304704200fd88219250d9ac16d90e6aa05fb11ad21116b44dea5b58a33a42960f82c2acf02010b042021618fc79e7ea2e3c910c5c8caf197e5c886b573b05cb975ec259a0c22f272b4".fromHex()
                val reply = ProtoBuf.singles(mapOf(
                    1 to ProtoVarInt(1),
                    2 to ProtoString(UUID.randomUUID().toString().uppercase()),
                    3 to ProtoLen(asn1)
                ))

                send(reply.renderStandalone(), 1008, handler)
            }

        }
    }

    private fun send(data: ByteArray, type: Int, handler: AlloyHandler) {
        Log.d(TAG, "sending data: ${data.hex()} type $type")
        handler.sendProtobuf(data, TOPIC, type, false)
    }
}