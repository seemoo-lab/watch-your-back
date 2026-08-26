package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.ProtobufMessage
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoBuf
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoI64
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoValue
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoVarInt
import net.rec0de.android.watchwitch.decoders.protobuf.ProtobufParser

object FindMyLocalDevice : AlloyService {
    override val handlesTopics = listOf("com.apple.private.alloy.findmylocaldevice")

    override fun acceptsMessageType(msg: AlloyMessage) = msg is ProtobufMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.PHONE

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is ProtobufMessage)
            throw Exception("FindMyLocalDevice expects ProtobufMessage but got $msg")

        val fields = ProtobufParser().parse(msg.payload).objs

        val timestamp = (fields[1]?.first() as ProtoI64?)?.asDate()
        println("[findmyld] ping: $timestamp")

        val replyBytes = ProtoBuf(mapOf(1 to listOf(ProtoVarInt(0) as ProtoValue))).renderStandalone()
        handler.sendProtobuf(replyBytes, "com.apple.private.alloy.findmylocaldevice", 1, isResponse = true)
    }
}