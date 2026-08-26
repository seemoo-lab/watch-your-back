package net.rec0de.android.watchwitch.transport

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.Utils
import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.bitmage.toBytes
import net.rec0de.android.watchwitch.bitmage.untilIndex
import net.rec0de.android.watchwitch.devices.Watch
import java.util.concurrent.atomic.AtomicLong

class ESPDispatcher {
    class EspSecrets(
        val spiI: ByteArray,
        val spiR: ByteArray,
        val keyI: ByteArray,
        val keyR: ByteArray,
        val saltI: ByteArray,
        val saltR: ByteArray,
        val isClassC: Boolean,
        val weInitiate: Boolean) {
        var ourSeq = AtomicLong(1)
    }

    private val spiLookup = mutableMapOf<String, EspSecrets>()
    private var classCContext: EspSecrets? = null
    private var classDContext: EspSecrets? = null

    private val espRcvBacklog = mutableListOf<Triple<ByteArray, ByteArray?, ByteArray?>>()

    fun registerEspSpi(secrets: EspSecrets) {
        spiLookup[secrets.spiI.hex()] = secrets
        spiLookup[secrets.spiR.hex()] = secrets

        if(secrets.isClassC)
            classCContext = secrets
        else
            classDContext = secrets

        val buffer = espRcvBacklog.toMutableList()
        espRcvBacklog.clear()
        buffer.forEach { receiveESP(it.first, it.second, it.third) }

        //Log.d(TAG, "got ESP secrets for SPIs ${secrets.spiI.hex()} and ${secrets.spiR.hex()}")
    }

    fun receiveESP(msg: ByteArray, sourceAddr: ByteArray?, destAddr: ByteArray?) {
        val spi = msg.untilIndex(4)
        val seq = msg.sliceArray(4 until 8)

        // implicit IV https://www.rfc-editor.org/rfc/rfc8750.html
        val iv = "00000000".fromHex() + seq
        val aad = spi + seq

        val context = spiLookup[spi.hex()]
        if(context == null) {
            Logger.logIKE("got ESP before crypto context ready", 0)
            espRcvBacklog.add(Triple(msg, sourceAddr, destAddr))
            return
        }

        val fromInitiator = context.spiR.contentEquals(spi)
        check(!(fromInitiator && context.weInitiate)) { "got ESP from initiator even though we initiated the connection?" }

        val salt = if(fromInitiator) context.saltI else context.saltR
        val key = if(fromInitiator) context.keyI else context.keyR

        val data = msg.fromIndex(8)
        val nonce = salt + iv

        val plain = when {
            Watch.espUseAESGCM -> Utils.aesGcmDecrypt(key, nonce, aad, data)
            else -> Utils.chachaPolyDecrypt(key, nonce, aad, data)
        }

        val nextHeader = plain[plain.size-1]
        val paddingLength = plain[plain.size-2].toInt()
        val payload = plain.untilIndex(plain.size-2-paddingLength)
        val padding = plain.sliceArray(plain.size-2-paddingLength until plain.size-2)

        //Log.d(TAG, "Decrypted ESP: next header $nextHeader padding ${padding.hex()} payload ${payload.hex()}")

        val source = sourceAddr ?: defaultSourceAddressFor(context.isClassC, context.weInitiate)
        val dest = destAddr ?: defaultDestinationAddressFor(context.isClassC, context.weInitiate)

        if(ServiceReferences.vpnConnection != null) {
            //Log.d(TAG, "Forwarding decrypted packet to local network...")
            ServiceReferences.vpnConnection!!.sendToLocalNetworkStack(payload, nextHeader, source, dest)
        }

    }

    fun sendESP(data: ByteArray, nextHeader: Int, classC: Boolean) {
        val secrets = if(classC) classCContext else classDContext

        if(secrets == null) {
            Log.d("ESPDispatcher", "trying to send before keys available, retrying in 200ms")
            Thread {
                runBlocking{ delay(200) }
                sendESP(data, nextHeader, classC)
            }.start()
            return
        }

        val spi = if(secrets.weInitiate) secrets.spiR else secrets.spiI
        val seq = (secrets.ourSeq.getAndIncrement().toUInt()).toBytes(ByteOrder.BIG)

        // implicit IV https://www.rfc-editor.org/rfc/rfc8750.html
        val iv = "00000000".fromHex() + seq
        val aad = spi + seq

        val salt = if(secrets.weInitiate) secrets.saltI else secrets.saltR
        val key = if(secrets.weInitiate) secrets.keyI else secrets.keyR
        val nonce = salt + iv

        val encLength = data.size + 2 // padding and next header fields
        val requiredPadding = (4-(encLength % 4)).toByte()

        val effectiveData = data + ByteArray(requiredPadding.toInt()){ i -> i.toByte() } + byteArrayOf(requiredPadding, nextHeader.toByte())

        //Log.d(TAG, "Encrypting using key ${key.hex()}, nonce ${nonce.hex()}, aad ${aad.hex()}, data ${effectiveData.hex()}")
        val cipher = when {
            Watch.espUseAESGCM -> Utils.aesGcmEncrypt(key, nonce, aad, effectiveData)
            else -> Utils.chachaPolyEncrypt(key, nonce, aad, effectiveData)
        }

        val espPacket = aad + cipher
        ServiceReferences.nrlpOverUdpService!!.sendEsp(espPacket, classC)
    }

    private fun defaultSourceAddressFor(isClassC: Boolean, weInitiate: Boolean): ByteArray = when {
        isClassC && weInitiate -> ServiceReferences.phonesideAddressC!!
        isClassC -> ServiceReferences.watchsideAddressC
        weInitiate -> ServiceReferences.phonesideAddressD!!
        else -> ServiceReferences.watchsideAddressD
    }

    private fun defaultDestinationAddressFor(isClassC: Boolean, weInitiate: Boolean): ByteArray = when {
        isClassC && weInitiate -> ServiceReferences.watchsideAddressC
        isClassC -> ServiceReferences.phonesideAddressC!!
        weInitiate -> ServiceReferences.watchsideAddressD
        else -> ServiceReferences.phonesideAddressD!!
    }
}