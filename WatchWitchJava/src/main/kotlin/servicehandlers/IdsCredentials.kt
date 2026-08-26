package net.rec0de.android.watchwitch.servicehandlers

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.rec0de.android.watchwitch.KeyStoreHelper
import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.LongTermStorage
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.alloy.AlloyController
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.decoders.aoverc.MPKeys
import net.rec0de.android.watchwitch.decoders.bplist.BPArray
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPData
import net.rec0de.android.watchwitch.decoders.bplist.BPDict
import net.rec0de.android.watchwitch.decoders.bplist.BPInt
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.BPSDict
import net.rec0de.android.watchwitch.decoders.bplist.BPTrue
import net.rec0de.android.watchwitch.devices.Watch
import net.rec0de.android.watchwitch.servicehandlers.health.HealthSync
import java.util.UUID

object IdsCredentials : AlloyService {

    private const val TOPIC = "com.apple.private.alloy.idscredentials"
    override val handlesTopics = listOf(TOPIC)
    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH
    private const val TAG = "IdsCredentials"

    private var gotKeys: Boolean = false
    private var sentKeys: Boolean = false

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        msg as DataMessage

        if(!BPListParser.bufferIsBPList(msg.payload)){
            Log.w(TAG, "unexpected non-bplist message: $msg")
            return
        }

        val bp = BPListParser().parse(msg.payload) as BPDict

        val command = (bp.values[BPAsciiString("command")]!! as BPInt).value.toInt()
        val uid = (bp.values[BPAsciiString("unique-id")]!! as BPAsciiString).value

        Log.d(TAG, "got command $command with uid $uid, data $bp")
        val alreadyGotAndSentKeys = gotKeys && sentKeys

        when(command) {
            11 -> {
                sendEncryptionKeys(uid, handler)
                sentKeys = true
                if(!gotKeys)
                    requestKeys(handler)
                WatchState.setPairingStage("sent local ids credentials")
                WatchState.incrementProgress()
            }
            12 -> {
                gotKeys = true
                registerEncryptionKeys(bp)
                WatchState.setPairingStage("got remote ids credentials")
                WatchState.incrementProgress()
            }
            15 -> {
                extractSyncInfo(bp)
                acknowledgeSync(uid, handler)
            }
            17 -> {}
            16 -> Log.d(TAG, "command is reply, don't need to do anything")
            18 -> extractServiceInfo(bp)
        }

        if(gotKeys && sentKeys && !alreadyGotAndSentKeys) {
            PushProxy.onIdsCredentialsDone()
            requestServiceInfo(handler)
            PBBridge.readyForBridgeInit()
            HealthSync.reloadKeys()
            //HealthSync.activationRestore()
        }
    }

    private fun extractSyncInfo(obj: BPDict) {
        val payload = obj.values[BPAsciiString("sync-payload")] as BPDict
        val acctInfo = payload.values[BPAsciiString("account-info")]

        if(acctInfo != null && acctInfo is BPArray) {
            extractAccountInfo(acctInfo)
        }
    }

    private fun extractServiceInfo(obj: BPDict) {
        val payload = obj.values[BPAsciiString("accountMap")] as BPDict

        payload.values.forEach {
            extractAccountInfo(it.value as BPArray)
        }
    }

    private fun extractAccountInfo(acctInfo: BPArray) {
        val accounts = acctInfo.values.map { it as BPDict }
        val ids = mutableSetOf<String?>()

        accounts.forEach { account ->
            val loginAs = (account.values[BPAsciiString("LoginAs")] as BPAsciiString?)?.value
            ids.add(loginAs)
            ids.add((account.values[BPAsciiString("AppleId")] as BPAsciiString?)?.value)

            if(account.values.containsKey(BPAsciiString("Profile"))) {
                val profile = account.values[BPAsciiString("Profile")]!! as BPDict
                ids.add((profile.values[BPAsciiString("Number")] as BPAsciiString?)?.value)
            }
        }

        WatchState.addStolenInfo(ids.filterNotNull().toSet())
    }

    private fun registerEncryptionKeys(dict: BPDict) {
        val classA = dict.values[BPAsciiString("encryption-class-a-key")]!! as BPData
        val keys = MPKeys.publicKeysFromDER(classA.value)
        LongTermStorage.setBytes(LongTermStorage.MP_REMOTE_PUBLIC_RSA_A, LongTermStorage.CONTEXT_WATCH, keys.rsaRemotePublic!!)
        LongTermStorage.setBytes(LongTermStorage.MP_REMOTE_PUBLIC_ECDSA_A, LongTermStorage.CONTEXT_WATCH, keys.ecdsaRemotePublic!!)
        Log.d(TAG, "got message protection keys")
    }

    private fun sendEncryptionKeys(uid: String, handler: AlloyHandler) {
        val dict = BPSDict(mapOf(
            "command" to BPInt(12),
            "unique-id" to BPAsciiString(uid),
            "success" to BPTrue,
            "hardware-version" to BPAsciiString(Watch.HW_VERSION),
            "device-name" to BPAsciiString(Watch.NAME),
            "identifier" to BPAsciiString(Watch.DEVICE_ID),
            // these are not OUR keys, but they have the right format at least
            "encryption-class-a-key" to BPData(renderLocalPublicKeys(1)),
            "encryption-class-c-key" to BPData(renderLocalPublicKeys(3)),
            "encryption-key" to BPData(renderLocalPublicKeys(4)),
            "private-device-data" to BPSDict(mapOf(
                "pv" to BPAsciiString(Watch.OS_VERSION),
                "pn" to BPAsciiString(Watch.OS_NAME),
                "pb" to BPAsciiString(Watch.BUILD),
                "h" to BPAsciiString("1"),
                "p" to BPAsciiString("0"),
                "ec" to BPAsciiString("2"),
                "c" to BPAsciiString("1"),
                "s" to BPAsciiString("0"),
                "t" to BPAsciiString("0"),
                "ap" to BPAsciiString("1"),
                "m" to BPAsciiString("0"),
                "v" to BPAsciiString("1"),
            ))
        ))
        send(dict, handler)
    }

    /*
      Produces ASN.1 encoded public keys in the format Apple devices expect
      I'm NOT writing a ASN.1 renderer here so we just fill in constant-length byte arrays into a template
     */
    fun renderLocalPublicKeys(dpc: Int): ByteArray {
        val ecdsa = KeyStoreHelper.aovercEcdsaPubkey(dpc, LongTermStorage.CONTEXT_WATCH)
        val rsa = KeyStoreHelper.aovercRsaPubkey(dpc, LongTermStorage.CONTEXT_WATCH)

        val preEcdsa = "3081f681430041".fromHex()
        val preRsa = "8281ae00ac".fromHex()

        val asn1 = preEcdsa + ecdsa + preRsa + rsa
        return asn1
    }


    private fun acknowledgeSync(uid: String, handler: AlloyHandler) {
        val dict = BPSDict(mapOf(
            "command" to BPInt(16),
            "unique-id" to BPAsciiString(uid),
            "success" to BPTrue
        ))
        send(dict, handler)
    }

    override fun onPhoneConnect(initialPairing: Boolean) {
        if(initialPairing) {
            val handler = AlloyController.getAnyHandler()!!
            Thread {
                runBlocking { delay(3000) }
                if(!gotKeys) {
                    requestKeys(handler)
                    WatchState.setPairingStage("requesting ids credentials")
                    WatchState.incrementProgress()
                }
            }.start()

        }
    }

    private fun requestKeys(handler: AlloyHandler) {
        val dict = BPSDict(mapOf(
            "command" to BPInt(11),
            "unique-id" to BPAsciiString(UUID.randomUUID().toString()),
        ))
        send(dict, handler)
    }

    private fun requestServiceInfo(handler: AlloyHandler) {
        val dict = BPSDict(mapOf(
            "command" to BPInt(17),
            "unique-id" to BPAsciiString(UUID.randomUUID().toString()),
            "serviceTypes" to BPArray(listOf(
                BPAsciiString("com.apple.ess"),
                BPAsciiString("com.apple.private.alloy.electrictouch"),
                BPAsciiString("com.apple.madrid"),
                BPAsciiString("com.apple.private.ac")
            ))
        ))
        send(dict, handler)
    }

    private fun send(dict: BPDict, handler: AlloyHandler) {
        Log.d(TAG, "sending dict: $dict")
        handler.sendData(dict.renderAsTopLevelObject(), TOPIC, UUID.randomUUID())
    }
}