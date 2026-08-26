package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPDict
import net.rec0de.android.watchwitch.decoders.bplist.BPListObject
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.NSDict

object AccountSync : AlloyService {

    override val handlesTopics = listOf("com.apple.private.alloy.accountssync")
    private const val TAG = "AccountSync"

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is DataMessage)
            throw Exception("$TAG expects DataMessage but got $msg")

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

        if(message.containsKey("pld"))
            return

        val pld = message.values[BPAsciiString("pld")] as NSDict

        if(pld.containsKey("acc"))
            return

        val acc = message.values[BPAsciiString("acc")] as BPDict

        if(acc.containsKey("accountProperties")) {
            val props = acc.values[BPAsciiString("accountProperties")]!!
            Log.d(TAG, "account properties: $props")
        }

        if(acc.containsKey("credential")) {
            val props = acc.values[BPAsciiString("credential")]!!
            Log.d(TAG, "credential: $props")
        }

    }
}