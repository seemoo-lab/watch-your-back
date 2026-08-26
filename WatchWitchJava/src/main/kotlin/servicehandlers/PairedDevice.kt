package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.ProtobufMessage
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.decoders.OpackParser

object PairedDevice : AlloyService {

    private const val TOPIC = "com.apple.private.alloy.sharing.paireddevice"
    override val handlesTopics = listOf(TOPIC)
    override fun acceptsMessageType(msg: AlloyMessage) = msg is ProtobufMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH
    private val TAG = "PairedDevice"

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        msg as ProtobufMessage

        try {
            val decoded = OpackParser().parseTopLevel(msg.payload)
            Log.d(TAG, "got message $decoded")

            send("ec436d65740943706d640843706d6c0243707373024370696301437773740a4370746d084370617432014002e04370697301436c73740b4370636c36333333333333d33f43706d78360000000000005940".fromHex(), handler)
        }
        catch (e: Exception) {
            Log.d(TAG, "expected OPACK payload, got ${msg.payload.hex()}")
        }

    }



    private fun send(data: ByteArray, handler: AlloyHandler) {
        Log.d(TAG, "sending data: ${data.hex()} ${OpackParser().parseTopLevel(data)}")
        handler.sendProtobuf(data, TOPIC, 0, false)
    }
}