package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.alloy.*
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.decoders.bplist.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URI
import java.net.URLConnection
import java.util.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*


object Anisette : AlloyService {

    private const val TAG = "Anisette"
    private const val TOPIC = "com.apple.private.alloy.anisette"
    private const val OMNISETTE_PORT = 8282
    override val handlesTopics = listOf(TOPIC)


    override fun acceptsMessageType(msg: AlloyMessage) = msg is DictionaryMessage
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

        if(message.values.containsKey(BPAsciiString("akcmd")))
            handleCmd(message, handler)
        else if(message.values.containsKey(BPAsciiString("akret")))
            handleResponse(message)
    }

    private fun handleCmd(msg: NSDict, handler: AlloyHandler) {
        val akcmd = (msg.values[BPAsciiString("akcmd")] as BPInt).value.toInt()
        val akid = msg.values[BPAsciiString("akid")] as BPAsciiString

        //val aktyp = (message.values[BPAsciiString("aktyp")] as BPInt).value.toInt()
        //val akarg = message.values[BPAsciiString("akarg")]

        when(akcmd) {
            1 -> {
                Log.d(TAG, "got command: fetch and provision")
                val data = genAnisetteDataMessage(akid.value)
                val rendered = data.renderAsTopLevelObject()
                Log.d(TAG, "sending reply: ${rendered.hex()}")
                handler.sendDictionary(rendered, TOPIC, UUID.randomUUID())
            }
            else -> Log.d(TAG, "unknown akcmd: $akcmd")
        }
    }

    private fun handleResponse(msg: NSDict) {
        val akret = (msg.values[BPAsciiString("akret")] as BPInt).value.toInt()
        val akid = msg.values[BPAsciiString("akid")] as BPAsciiString

        //val aktyp = (message.values[BPAsciiString("aktyp")] as BPInt).value.toInt()
        //val akarg = message.values[BPAsciiString("akarg")]
    }

    fun requestAnisetteData(handler: AlloyHandler) {
        val request = BPSDict(mapOf(
            "aktyp" to BPInt(0),
            "akcmd" to BPInt(0),
            "akid" to BPAsciiString(UUID.randomUUID().toString()),
            "akarg" to BPTrue
        ))

        Log.d(TAG, "sending anisette request $request")
        handler.sendDictionary(request.renderAsTopLevelObject(), TOPIC, UUID.randomUUID())
    }

    private fun genAnisetteDataMessage(id: String): CodableBPListObject {

        val omnisette = getOmnisetteData()

        val data = BPDict(mapOf(
            BPAsciiString("_oneTimePassword") to BPAsciiString(omnisette.first),
            BPAsciiString("_machineID") to BPAsciiString(omnisette.second),
            BPAsciiString("_routingInfo") to BPInt(omnisette.third),
            BPAsciiString("\$class") to BPDict(mapOf(
                BPAsciiString("\$classname") to  BPAsciiString("AKAnisetteData"),
                BPAsciiString("\$classes") to BPArray(listOf(BPAsciiString("AKAnisetteData"), BPAsciiString("NSObject")))
            ))
        ))

        val dict = BPDict(mapOf(
            BPAsciiString("akrid") to BPAsciiString(id),
            BPAsciiString("akid") to BPAsciiString(UUID.randomUUID().toString()),
            BPAsciiString("aksuc") to BPTrue,
            BPAsciiString("aktyp") to BPInt(1),
            BPAsciiString("akret") to KeyedArchiveEncoder().encode(data)
        ))

        return dict
    }

    fun getOmnisetteData(): Triple<String, String, Int> {
        var url = URI.create("http://127.0.0.1:${OMNISETTE_PORT}/").toURL()
        val con: URLConnection = url.openConnection()
        val input = BufferedReader(InputStreamReader(con.getInputStream()))

        val json = input.readText()
        input.close()

        val response = Json.decodeFromString<Map<String,String>>(json)
        println(response)

        val otp = response["X-Apple-I-MD"]!!
        val machineID = response["X-Apple-I-MD-M"]!!
        val routingID = response["X-Apple-I-MD-RINFO"]!!.toInt()

        return Triple(otp, machineID, routingID)
    }
}