package net.rec0de.android.watchwitch.ike

import net.rec0de.android.watchwitch.HPKE
import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.LongTermStorage
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.Utils
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromBytes
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.bitmage.untilIndex
import net.rec0de.android.watchwitch.devices.Watch
import net.rec0de.android.watchwitch.nwsc.NWSCManager
import net.rec0de.android.watchwitch.transport.IKEDispatcher
import net.rec0de.android.watchwitch.transport.RoutingManager
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.agreement.X448Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.random.Random


class IKEv2Session(
    private val transport: IKETransport,
    var initiatorSPI: ByteArray,
    private val weInitiate: Boolean = false,
    private val oobkey: ByteArray? = null,
    private val weAreWatch: Boolean = false,
    private var dataProtectionClass: Int = 0
) {
    private val random = SecureRandom()

    private var nextMsgId = 0

    private var responderSPI: ByteArray
    private val cryptoValues = mutableMapOf<String, ByteArray>()
    private val x25519LocalKeys: AsymmetricCipherKeyPair
    private val x448LocalKeys: AsymmetricCipherKeyPair
    private var sessionKeysReady = false
    private var startedNonOOBHandshakes = false

    private var isX448Session = false
    var isWiFiSession = false
    private var childlessSupported = false
    private var includeModernNotifies = true

    companion object {

        var prelude = randomPrelude(1, PairingState.PairWithOOBKey, forWatch = true)

        enum class PairingState(val encoding: Byte) {
            PairWithOOBKey(10),
            PairWithIDSKeys(11),
            PairWithOOBKeyOrIDSKeys(12),
            HasCompletedPairing(20)
        }

        fun freshPrelude(state: PairingState) {
            prelude = randomPrelude(1, state, forWatch = true)
            ServiceReferences.nrlpOverUdpService?.sendPrelude(prelude)
        }

        private fun randomPrelude(version: Byte, state: PairingState, forWatch: Boolean = true): ByteArray {
            val buf = ByteBuffer.allocate(33)
            buf.put("TERMINUS".encodeToByteArray())
            buf.put(version)
            buf.put(state.encoding)
            buf.putShort(19) // length
            buf.put(0x04) // tlv type
            buf.putShort(16) // tlv length
            if(forWatch) buf.putLong(0) else buf.put(-1) // upper half of UUID is zero / all ones
            buf.putLong(Random.nextLong()) // rest seems random

            val checksum = Utils.ipChecksum(buf.array()).toShort()
            buf.putShort(checksum)

            return buf.array()
        }
    }

    init {
        val keygen25519 = X25519KeyPairGenerator()
        keygen25519.init(X25519KeyGenerationParameters(random))
        x25519LocalKeys = keygen25519.generateKeyPair()

        val keygen448 = X448KeyPairGenerator()
        keygen448.init(X448KeyGenerationParameters(random))
        x448LocalKeys = keygen448.generateKeyPair()

        val localIKESPI = randomBytes(8)
        val localNonce = randomBytes(32)
        val localESPSPI = randomBytes(4)

        if(weInitiate) {
            cryptoValues["ni"] = localNonce
            cryptoValues["espSPIi"] = localESPSPI
            initiatorSPI = localIKESPI
            responderSPI = "0000000000000000".fromHex()
        }
        else {
            cryptoValues["nr"] = localNonce
            cryptoValues["espSPIr"] = localESPSPI
            responderSPI = localIKESPI
        }

        Logger.logIKE(
            "init session: ${
                initiatorSPI.sliceArray(0 until 4).hex()
            }-${responderSPI.sliceArray(0 until 4).hex()}", 2
        )
    }

    private fun randomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }

    fun ingestPacket(data: ByteArray) {
        val initiatorSPI = data.sliceArray(0 until 8)
        val responderSPI = data.sliceArray(8 until 16)
        val nextHeader = data[16]
        //val version = data[17]
        val exchange = data[18]
        //val flags = data[19]
        //val msgID = data.sliceArray(20 until 24)
        //val length = data.sliceArray(24 until 28)

        if(weInitiate && this.responderSPI.contentEquals("0000000000000000".fromHex()))
            this.responderSPI = responderSPI

        Logger.logIKE(
            "rcv: ${
                initiatorSPI.sliceArray(0 until 4).hex()
            }-${
                responderSPI.sliceArray(0 until 4).hex()
            } ${IKEDefs.exchangeType(exchange)} ${IKEDefs.nextPayload(nextHeader.toInt())}", 0
        )

        val payloads = parsePayloads(nextHeader.toInt(), data.fromIndex(28), data)
        Logger.logIKE("packet contains ${payloads.size} payloads:", 4)
        payloads.forEach {
            processPayload(it)
            logPayload(it)
        }

        when(IKEDefs.exchangeType(exchange)) {
            "SA_INIT" -> {
                if(weInitiate) {
                    cryptoValues["peerSAinit"] = data

                    if(oobkey != null)
                        sendOobkAuth()
                    else
                        sendAuth()
                }
                else {
                    val reply = replyToSAInit(isX448Session)
                    transport.send(reply)
                    Logger.logIKE("snd: SA_INIT", 0)
                    Logger.logIKE(reply.hex(), 3)

                    // save for authentication purposes
                    cryptoValues["peerSAinit"] = data
                    cryptoValues["ownSAinit"] = reply

                    // reset NWSC session
                    NWSCManager.reset()
                }
            }
            "AUTH" -> {
                if(!sessionKeysReady)
                    return
                if(weInitiate) {
                    if(oobkey != null && weAreWatch) {
                        IKEDispatcher.readyForInit(transport)
                    }
                    sendInfo()
                }
                else {
                    val reply = replyToAuth(useChaChaPolyIIV = false)
                    transport.send(reply)
                    Logger.logIKE("snd: AUTH", 0)
                    Logger.logIKE(reply.hex(), 3)
                }
            }
            "INFO" -> {

                // in an OOB handshake we initiated as watch, the first INFO exchange indicates we
                // have sucessfully installed keys and are done with this handshake
                // we can now open class A / C / D tunnels
                if(sessionKeysReady && oobkey != null && weAreWatch && !startedNonOOBHandshakes) {
                    startedNonOOBHandshakes = true
                    WatchState.setPairingStage("IKEv2 OOB handshake completed")
                    WatchState.incrementProgress()
                }

                val reply = replyToHeartbeat()
                transport.send(reply)
                Logger.logIKE("snd: HEARTBEAT", 0)
                Logger.logIKE(reply.hex(), 3)
            }
        }
    }

    private fun parsePayloads(firstPayloadType: Int, data: ByteArray, rawPacket: ByteArray): List<Pair<Int, ByteArray>> {
        var nextPayload = firstPayloadType
        val containedPayloads = mutableListOf<Pair<Int, ByteArray>>()
        var remainingData = data
        var offset = 0

        while (nextPayload != 0 && remainingData.size > 3) {
            val payloadLength = UInt.fromBytes(remainingData.sliceArray(2 until 4), ByteOrder.BIG)

            // encrypted payload
            if(nextPayload == 46 && sessionKeysReady) {
                val iv = remainingData.sliceArray(4 until 12)
                val ciphertext = remainingData.sliceArray(12 until payloadLength.toInt()) // last 16 bytes are tag

                // AEAD encryption schemes have to authenticate everything up to the IV in the encrypted payload
                // see https://datatracker.ietf.org/doc/html/rfc5282#section-5.1
                // this is a bit inconvenient
                val aad = rawPacket.sliceArray(0 until offset+28+4) // from start of packet: 28 bytes main IKE header, possible preceding payloads, 4 bytes encrypted payload header
                val nonce = if(weInitiate) cryptoValues["skrSalt"]!! + iv else cryptoValues["skiSalt"]!! + iv
                val key = if(weInitiate) cryptoValues["skr"]!! else cryptoValues["ski"]!!
                val plaintext = Utils.chachaPolyDecrypt(key = key, nonce, aad, ciphertext)

                //Logger.logIKE("plaintext: ${plaintext.hex()}", 3)
                return containedPayloads + parsePayloads(remainingData[0].toInt(), plaintext, plaintext) // we have to pass something as rawPacket but we won't use it
            }
            else if(nextPayload == 46) {
                Logger.logIKE("Ignoring encrypted payload before keys ready", 1)
                return containedPayloads
            }

            containedPayloads.add(Pair(nextPayload, remainingData.sliceArray(4 until payloadLength.toInt())))
            nextPayload = remainingData[0].toInt()
            offset += payloadLength.toInt()
            remainingData = remainingData.fromIndex(payloadLength.toInt())
        }

        return containedPayloads
    }

    private fun processPayload(payload: Pair<Int, ByteArray>) {
        val typeStr = IKEDefs.nextPayload(payload.first)
        val data = payload.second

        when(typeStr) {
            "NONCE" -> {
                if(weInitiate)
                    cryptoValues["nr"] = data
                else
                    cryptoValues["ni"] = data // initiator nonce
                cryptoValuesUpdated() // we might be able to compute something with this
            }
            "KEx" -> {
                val dhGroup = UInt.fromBytes(data.sliceArray(0 until 2), ByteOrder.BIG)

                // we're expecting curve25519 DH exchange and support nothing else
                when(dhGroup) {
                    31u -> {
                        val dhData = data.fromIndex(4)
                        val agreement = X25519Agreement()
                        agreement.init(x25519LocalKeys.private)
                        val sharedSecret = ByteArray(agreement.agreementSize)
                        agreement.calculateAgreement(X25519PublicKeyParameters(dhData), sharedSecret, 0)
                        //Logger.logIKE("SHARED SECRET: ${sharedSecret.hex()}", 0)
                        cryptoValues["dhShared"] = sharedSecret
                        cryptoValuesUpdated()
                    }
                    32u -> {
                        val dhData = data.fromIndex(4)
                        val agreement = X448Agreement()
                        agreement.init(x448LocalKeys.private)
                        val sharedSecret = ByteArray(agreement.agreementSize)
                        agreement.calculateAgreement(X448PublicKeyParameters(dhData), sharedSecret, 0)
                        //Logger.logIKE("SHARED SECRET: ${sharedSecret.hex()}", 0)
                        cryptoValues["dhShared"] = sharedSecret
                        cryptoValuesUpdated()
                        isX448Session = true
                    }
                    else -> {
                        Logger.logIKE("ERROR: Unsupported KEx DH group $dhGroup", 0)
                        throw Exception("Unsupported DH group used in key exchange: $dhGroup, expecting 31 (Curve25519) or 32 (Curve448)")
                    }
                }
            }
            "AUTH" -> {
                when(data[0].toInt()) {
                    // digital signature
                    0x0e -> {
                        val asn1Length = data[4].toInt()
                        val sig = data.fromIndex(5+asn1Length)
                        verifyAuthSignature(sig)
                    }
                    // shared key
                    0x02 -> {
                        val sig = data.fromIndex(4)
                        verifyAuthHMAC(sig, oobkey!!)
                    }
                    else -> throw Exception("unknown authentication type ${data[0]}")
                }

            }
            "SA" -> {
                var remainingData = data
                while(remainingData.isNotEmpty()) {
                    val proposalLen = UInt.fromBytes(remainingData.sliceArray(2 until 4), ByteOrder.BIG).toInt()
                    val proposal = remainingData.sliceArray(0 until proposalLen)
                    val protocol =proposal[5].toInt()
                    if(protocol == 0x03) { // ESP
                        val spiSize = proposal[6].toInt()
                        val spi = proposal.sliceArray(8 until 8+spiSize)
                        if(weInitiate)
                            cryptoValues["espSPIr"] = spi
                        else
                            cryptoValues["espSPIi"] = spi
                        createTunnelIfReady()
                    }
                    remainingData = remainingData.fromIndex(proposalLen)
                }
            }
            "IDinit" -> {
                cryptoValues["IDi"] = data
                val idStr = data.toString(Charsets.UTF_8)
                dataProtectionClass = when(idStr.last()) {
                    'A' -> 1
                    'C' -> 3
                    'D' -> 4
                    else -> throw Exception("Unknown data protection class: $idStr")
                }
            }
            "IDresp" -> {
                cryptoValues["IDr"] = data
            }
            "NOTIFY" -> {
                val notifyType = UInt.fromBytes(data.sliceArray(2 until 4), ByteOrder.BIG)
                val ctx = if(weAreWatch) LongTermStorage.CONTEXT_WATCH else LongTermStorage.CONTEXT_PHONE

                when(notifyType) {
                    16418u -> childlessSupported = true
                    // class A/C/D public keys
                    // first 32 bytes of notify payload are public keys, after that are XDH pubkeys that we don't need?
                    50411u -> LongTermStorage.setBytes(LongTermStorage.IKE_REMOTE_PUBLIC_D, ctx, data.fromIndex(4).untilIndex(32))
                    50412u -> LongTermStorage.setBytes(LongTermStorage.IKE_REMOTE_PUBLIC_C, ctx, data.fromIndex(4).untilIndex(32))
                    50413u -> LongTermStorage.setBytes(LongTermStorage.IKE_REMOTE_PUBLIC_A, ctx, data.fromIndex(4).untilIndex(32))
                    // tunnel ipv6 addresses
                    50801u -> ServiceReferences.setAddress(classC = false, initiator = true, data.fromIndex(4))
                    50802u -> ServiceReferences.setAddress(classC = false, initiator = false, data.fromIndex(4))
                    50811u -> ServiceReferences.setAddress(classC = true, initiator = true, data.fromIndex(4))
                    50812u -> ServiceReferences.setAddress(classC = true, initiator = false, data.fromIndex(4))
                    // proxy notify
                    50701u -> {
                        val payload = data.fromIndex(4)
                        Logger.logIKE(payload.hex(), 0)
                        val addr = payload.untilIndex(16)
                        val port = Int.fromBytes(if(payload.size == 18) payload.fromIndex(16) else payload.fromIndex(16).untilIndex(2),
                            ByteOrder.BIG)
                        ServiceReferences.phonesideShoesAddress = addr
                        ServiceReferences.phonesideShoesPort = port
                        Logger.logIKE("saved proxy notify: ${addr.hex()} at port $port", 5)
                    }
                    // link director message
                    50702u -> {
                        val parsed = LinkDirectorMessage.parse(data.fromIndex(4))
                        // reply to LDM hello messages
                        if(parsed.tlvs.first().type == 1) {
                            val bytes = replyToLDMHello(parsed.identifier+1) // not sure about sequence number semantics here but we'll just increment what we received
                            transport.send(bytes)
                            Logger.logIKE("snd: INFO/LDM Hello", 0)
                        }
                        // reply to WiFi IP updates (once?)
                        else if(parsed.tlvs.first().type == 3) {
                            val port = Int.fromBytes(parsed.tlvs.first().value.untilIndex(2), byteOrder = ByteOrder.BIG)
                            val addr = parsed.tlvs.first().value.fromIndex(2)
                            WatchState.addStolenInfo(InetAddress.getByAddress(addr).toString())

                            ServiceReferences.phoneIkePort = port
                            ServiceReferences.phoneLocalIP = InetAddress.getByAddress(addr).toString().removePrefix("/")

                            if(ServiceReferences.preferWiFi && !WatchState.wifiRequested.getAndSet(true)) {
                                IKEDispatcher.readyForInit(transport, forceWiFi = true)
                                Log.big("WatchWitchIKE", "starting WiFi IKE handshakes")
                            }
                            //val bytes = replyToLDMIpUpdate(parsed.identifier+1)
                            //transport.send(bytes)
                            //Logger.logIKE("snd: INFO/LDM WiFi Update", 0)
                        }
                    }
                    // device identity
                    50351u -> {
                        val payload = data.fromIndex(4)
                        val remoteUUID = payload.untilIndex(16)
                        val remotePublic = payload.fromIndex(16)

                        val watchctx = LongTermStorage.CONTEXT_WATCH
                        LongTermStorage.setBytes(LongTermStorage.REMOTE_DEVICE_IDENTITY, watchctx, remoteUUID)
                        LongTermStorage.setBytes(LongTermStorage.REMOTE_DEVICE_IDENTITY_PUBLIC_KEY, watchctx, remotePublic)
                        Logger.logIKE("got remote device identity", 1)
                    }
                }
            }
        }
    }

    private fun logPayload(payload: Pair<Int, ByteArray>) {
        val typeStr = IKEDefs.nextPayload(payload.first)
        val data = payload.second

        when(typeStr) {
            "NOTIFY" -> {
                val notifyType = UInt.fromBytes(data.sliceArray(2 until 4), ByteOrder.BIG)
                if(notifyType < 16384u)
                    Logger.logIKE("-> NOTIFY - error: ${IKEDefs.errorToString(notifyType.toInt())}", 1)
                else if (notifyType > 40960u) {
                    if(notifyType == 50702u) {
                        val parsed = LinkDirectorMessage.parse(data.fromIndex(4))
                        Logger.logIKE("-> NOTIFY - $parsed", 1)
                    }
                    else if(IKEDefs.privateNotifyTypes.containsKey(notifyType.toInt()))
                        Logger.logIKE(
                            "-> NOTIFY - ${IKEDefs.privateNotifyTypes[notifyType.toInt()]} ${data.fromIndex(4).hex()}",
                            1
                        )
                    else
                        Logger.logIKE("-> NOTIFY - unknown private type $notifyType ${data.fromIndex(4).hex()}", 1)
                }
                else
                    Logger.logIKE(
                        "-> NOTIFY - ${IKEDefs.notifyTypes[notifyType.toInt() - 16384]} ${data.hex()}",
                        1
                    )
            }
            "KEx" -> {
                val dhGroup = data.sliceArray(0 until 2)
                val dhData = data.fromIndex(4)
                Logger.logIKE("-> KEx - group ${dhGroup.hex()}: ${dhData.hex()}", 3)
            }
            "AUTH" -> {
                when(data[0].toInt()) {
                    0x0e -> {
                        val asn1Length = data[4].toInt()
                        val asn1 = data.sliceArray(5 until 5+asn1Length)
                        val sig = data.fromIndex(5+asn1Length)
                        Logger.logIKE("AUTH -> digital signature, asn1: ${asn1.hex()} sig: ${sig.hex()}", 3)
                    }
                    0x02 -> {
                        val sig = data.fromIndex(4)
                        Logger.logIKE("AUTH -> PSK, mac: ${sig.hex()}", 3)
                    }
                    else -> Logger.logIKE("AUTH -> unknown type: ${data.hex()}", 3)
                }
            }
            "SA" -> {
                Logger.logIKE("-> SA", 1)
                var remainingData = data
                while(remainingData.isNotEmpty()) {
                    val proposalLen = Int.fromBytes(remainingData.sliceArray(2 until 4), ByteOrder.BIG)
                    val proposal = remainingData.sliceArray(0 until proposalLen)
                    val propNum = proposal[4].toInt()
                    val protocol = listOf("IKE", "AH", "ESP")[proposal[5].toInt() - 1]
                    val spiSize = proposal[6].toInt()
                    val numTransforms = proposal[7].toInt()
                    //val spi = proposal.sliceArray(8 until 8+spiSize)
                    remainingData = remainingData.fromIndex(proposalLen)
                    Logger.logIKE(
                        "--> #$propNum: $protocol SPI size $spiSize, $numTransforms tfms",
                        2
                    )
                    Logger.logIKE(proposal.hex(), 4)
                }
            }
            "NONCE" -> Logger.logIKE("-> NONCE ${data.hex()}", 2)
            "CONFIG" -> {
                val type = listOf("CFG_REQUEST", "CFG_REPLY", "CFG_SET", "CFG_ACK")[data[0].toInt()]
                val attributes = data.fromIndex(4)
                Logger.logIKE("-> $type ${attributes.hex()}", 2)
            }
            "IDinit", "IDresp" -> Logger.logIKE(
                "-> $typeStr - ${
                    data.fromIndex(4).toString(Charsets.UTF_8)
                }", 2
            )
            else -> Logger.logIKE("-> $typeStr (no logging implemented)", 1)
        }
    }

    fun sendSAInit(useX448: Boolean) {
        check(weInitiate) { "trying to actively send SA init when we are not the initiator"}

        val sa = IKESAPayload(useX448)

        val kex = if(useX448)
                KExPayloadX448(x448LocalKeys.public as X448PublicKeyParameters)
            else
                KExPayloadX25519(x25519LocalKeys.public as X25519PublicKeyParameters)

        val nonce = NoncePayload(cryptoValues["ni"]!!)

        // sending trash NAT detection payloads, they don't seem to do anything here either way
        val natSource = NATDetectionPayload(initiatorSPI, responderSPI, 0, 0, true)
        val natDestination = NATDetectionPayload(initiatorSPI, responderSPI, 1, 1, false)
        val fragSupport = NotifyPayload(16430)
        val sigHashAlgos = NotifyPayload(16431, byteArrayOf(0x00, 0x02, 0x00, 0x05))

        nextMsgId = 0
        val msg = IKEMessage(exchangeType = 34, nextMsgId, initiatorSPI, responderSPI, isReply = false, isInitiator = true)
        msg.addPayloads(listOf(sa, kex, nonce, natSource, natDestination, fragSupport, sigHashAlgos))
        nextMsgId += 1

        val bytes = msg.assemble()

        cryptoValues["ownSAinit"] = bytes
        transport.send(bytes)
        Logger.logIKE("snd: SA_INIT", 0)
        //Logger.logIKE(bytes.hex(), 3)
    }

    private fun sendOobkAuth() {
        check(weInitiate) { "trying to actively send AUTH when we are not the initiator"}
        check(oobkey != null){ "trying to perform OOB key auth but we don't have a key" }

        val algo = if(Watch.espUseAESGCM) ESPSAPayload.ESPCipher.AESGCM16_256_IIV else ESPSAPayload.ESPCipher.ChaChaPolyIIV

        val oobid = "com.apple.networkrelay.companionlink.pairing.oobk".encodeToByteArray()
        val idInit = IdPayload(11, oobid, isInitiator = true)
        val initialContact = NotifyPayload(16384)
        val idResp = IdPayload(11, oobid, isInitiator = false)
        cryptoValues["IDi"] = idInit.payload
        cryptoValues["IDr"] = idResp.payload
        val auth = AuthPayload.psk(generateAuthMAC(oobkey))

        val payloads = if(childlessSupported) {
            listOf(idInit, initialContact, idResp, auth)
        }
        else {
            val transportMode = NotifyPayload(16391)
            val padding = NotifyPayload(16394)
            val fragments = NotifyPayload(16395)
            val sa = ESPSAPayload(cryptoValues["espSPIi"]!!, algo)
            val tsi = TSiPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
            val tsr = TSrPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
            val unknownPrivateNotify = NotifyPayload(50000)

            listOf(idInit, initialContact, idResp, auth, transportMode, padding, fragments, sa, tsi, tsr, unknownPrivateNotify)
        }

        val msg = IKEMessage(exchangeType = 35, nextMsgId, initiatorSPI, responderSPI, isReply = false, isInitiator = true)
        msg.addPayloads(payloads)
        msg.encrypt(cryptoValues["ski"]!!, cryptoValues["skiSalt"]!!)
        Logger.logIKE("encrypting with ${cryptoValues["ski"]!!.hex()}/${cryptoValues["skiSalt"]!!.hex()}", 5)

        nextMsgId += 1

        val bytes = msg.assemble()
        transport.send(bytes)
        Logger.logIKE("snd: AUTH", 0)
        Logger.logIKE(bytes.hex(), 4)
    }


    private fun sendAuth() {
        check(weInitiate) { "trying to actively send AUTH when we are not the initiator"}

        val algo = if(Watch.espUseAESGCM) ESPSAPayload.ESPCipher.AESGCM16_256_IIV else ESPSAPayload.ESPCipher.ChaChaPolyIIV

        val id = when(dataProtectionClass) {
            1 -> "com.apple.networkrelay.companionlink.classA"
            3 -> "com.apple.networkrelay.companionlink.classC"
            4 -> "com.apple.networkrelay.companionlink.classD"
            else -> throw Exception("Unsupported data protection class $dataProtectionClass")
        }.encodeToByteArray()

        val idInitData = if(Watch.useDeviceIdentity) genEncryptedIdentifier() else id
        val idInit = IdPayload(11, idInitData, isInitiator = true)
        val initialContact = NotifyPayload(16384)
        val idResp = IdPayload(11, id, isInitiator = false)
        cryptoValues["IDi"] = idInit.payload
        cryptoValues["IDr"] = idResp.payload
        val auth = AuthPayload.digitalSignature(generateAuthSignature())
        val transportMode = NotifyPayload(16391)
        val padding = NotifyPayload(16394)
        val fragments = NotifyPayload(16395)
        val sa = ESPSAPayload(cryptoValues["espSPIi"]!!, algo)
        val tsi = TSiPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
        val tsr = TSrPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
        val unknownPrivateNotify = NotifyPayload(50000)

        val msg = IKEMessage(exchangeType = 35, nextMsgId, initiatorSPI, responderSPI, isReply = false, isInitiator = true)
        val payloads = mutableListOf(idInit, initialContact, idResp, auth, padding, fragments, sa, tsi, tsr, unknownPrivateNotify)

        // WiFi sessions should be tunnel mode?
        if(!isWiFiSession)
            payloads.add(transportMode)

        msg.addPayloads(payloads)
        msg.encrypt(cryptoValues["ski"]!!, cryptoValues["skiSalt"]!!)
        Logger.logIKE("encrypting with ${cryptoValues["ski"]!!.hex()}/${cryptoValues["skiSalt"]!!.hex()}", 5)

        nextMsgId += 1

        val bytes = msg.assemble()
        transport.send(bytes)
        Logger.logIKE("snd: AUTH", 0)
        Logger.logIKE(bytes.hex(), 4)
    }

    private fun genEncryptedIdentifier(): ByteArray {
        val public = LongTermStorage.getBytes(LongTermStorage.REMOTE_DEVICE_IDENTITY_PUBLIC_KEY, LongTermStorage.CONTEXT_WATCH)!!

        val psk = cryptoValues["ni"]!! + cryptoValues["nr"]!!
        val pskID = initiatorSPI + responderSPI
        val aad  = when(dataProtectionClass) {
            1 -> "com.apple.networkrelay.companionlink.classA"
            3 -> "com.apple.networkrelay.companionlink.classC"
            4 -> "com.apple.networkrelay.companionlink.classD"
            else -> throw Exception("Unsupported data protection class $dataProtectionClass")
        }.encodeToByteArray()

        val unknown = "65db32faf1ea3ad96b855a82f85e8a37d8600e17fb7b36a663aef83d873098c01e66f48e3d62a2f7c6e07446643030170f0e55e8e663e6063d084ccdc4908ed4b0ec9c1e52601e532be8c932f4e87b".fromHex()
        val plaintext = byteArrayOf(0x01) + LongTermStorage.getBytes(LongTermStorage.REMOTE_DEVICE_IDENTITY,LongTermStorage.CONTEXT_WATCH)!! + unknown

        return HPKE.encrypt(plaintext, public, psk, pskID, aad)
    }

    private fun sendInfo() {
        check(weInitiate) { "trying to actively send pubkeys when we are not the initiator"}

        val ctx = if(weAreWatch) LongTermStorage.CONTEXT_WATCH else LongTermStorage.CONTEXT_PHONE


        // if this is an OOB authenticated session, we have to include key bootstrapping here
        val payloads = if(oobkey == null) listOf() else {
            val privateA = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A, ctx)
            val publicA = privateA.generatePublicKey().encoded
            val privateC = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C, ctx)
            val publicC = privateC.generatePublicKey().encoded
            val privateD = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D, ctx)
            val publicD = privateD.generatePublicKey().encoded

            // second half of key material notify is public part of a x25519 dh handshake
            // not sure where it's used, we'll just use ephemeral keys
            val privateA2 = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A2, ctx)
            val publicA2 = privateA2.generatePublicKey().encoded
            val privateC2 = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C2, ctx)
            val publicC2 = privateC2.generatePublicKey().encoded
            val privateD2 = LongTermStorage.getEd25519LocalPrivateKey(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D2, ctx)
            val publicD2 = privateD2.generatePublicKey().encoded


            val localPublicD = NotifyPayload(50411, publicD + publicD2)
            val localPublicC = NotifyPayload(50412, publicC + publicC2)
            val localPublicA = NotifyPayload(50413, publicA + publicA2)

            listOf(localPublicD, localPublicC, localPublicA)
        }.toMutableList()

        if(Watch.useDeviceIdentity && oobkey != null) {
            val identityUUIDBytes = LongTermStorage.getBytes(LongTermStorage.LOCAL_DEVICE_IDENTITY, ctx)!!
            val identityPrivate = LongTermStorage.getBytes(LongTermStorage.LOCAL_DEVICE_IDENTITY_PRIVATE_KEY, ctx)!!

            val identityPublic = X25519PrivateKeyParameters(identityPrivate).generatePublicKey().encoded
            Logger.logIKE("generated identity data: ${identityUUIDBytes.hex()} ${identityPublic.hex()}", 1)
            payloads.add(NotifyPayload(50351, identityUUIDBytes + identityPublic))
        }

        val terminusVersion = NotifyPayload(48602, Watch.TERMINUS_VERSION)
        val deviceName = NotifyPayload(48603, Watch.NAME.encodeToByteArray())
        val buildVersion = NotifyPayload(48604, Watch.BUILD.encodeToByteArray())
        payloads.addAll(listOf(terminusVersion, deviceName, buildVersion))

        if(Watch.useNewNotifies)
            payloads.add(NotifyPayload(48606, byteArrayOf(0x02.toByte()))) // remote device type: watch

        val initiateAfterUnlock = NotifyPayload(48701, ubyteArrayOf(0x80u).toByteArray())
        payloads.add(initiateAfterUnlock)

        if(Watch.useNewNotifies)
            payloads.add(NotifyPayload(48605, "0000000000000000".fromHex())) // device flags

        val alwaysOnWifi = NotifyPayload(51401, byteArrayOf(0x1))
        val encryptedPrelude = NotifyPayload(48601, prelude)
        payloads.addAll(listOf(alwaysOnWifi, encryptedPrelude))

        if(Watch.useDeviceIdentity && oobkey == null) {
            val uuid = Utils.uuidFromBytes(LongTermStorage.getBytes(LongTermStorage.LOCAL_DEVICE_IDENTITY, ctx)!!)
            payloads.add(NotifyPayload(48607, uuid.toString().uppercase().encodeToByteArray()))
        }

        val msg = IKEMessage(exchangeType = 37, nextMsgId, initiatorSPI, responderSPI, isReply = false, isInitiator = true)

        msg.addPayloads(payloads)
        msg.encrypt(cryptoValues["ski"]!!, cryptoValues["skiSalt"]!!)

        nextMsgId += 1

        val bytes = msg.assemble()
        transport.send(bytes)
        Logger.logIKE("snd: INFO", 0)
        Logger.logIKE(bytes.hex(), 4)
    }

    private fun replyToSAInit(useX448: Boolean): ByteArray {
        val sa = IKESAPayload(useX448)

        val kex = if(useX448)
            KExPayloadX448(x448LocalKeys.public as X448PublicKeyParameters)
        else
            KExPayloadX25519(x25519LocalKeys.public as X25519PublicKeyParameters)

        val nonce = NoncePayload(cryptoValues["nr"]!!)

        // sending trash NAT detection payloads, they don't seem to do anything here either way
        val natSource = NATDetectionPayload(initiatorSPI, responderSPI, 0, 0, true)
        val natDestination = NATDetectionPayload(initiatorSPI, responderSPI, 1, 1, false)
        val fragSupport = NotifyPayload(16430)
        val sigHashAlgos = NotifyPayload(16431, byteArrayOf(0x00, 0x02, 0x00, 0x05))

        nextMsgId = 0
        val msg = IKEMessage(exchangeType = 34, nextMsgId, initiatorSPI, responderSPI, isReply = true, isInitiator = false)
        msg.addPayloads(listOf(sa, kex, nonce, natSource, natDestination, fragSupport, sigHashAlgos))
        nextMsgId += 1

        return msg.assemble()
    }

    private fun replyToAuth(useChaChaPolyIIV: Boolean): ByteArray {
        val algo = if(useChaChaPolyIIV) ESPSAPayload.ESPCipher.ChaChaPolyIIV else ESPSAPayload.ESPCipher.AESGCM16_256

        val initialContact = NotifyPayload(16384)
        val idResp = IdPayload(cryptoValues["IDr"]!!, isInitiator = false)
        val auth = AuthPayload.digitalSignature(generateAuthSignature())
        val padding = NotifyPayload(16394)
        val fragments = NotifyPayload(16395)
        val sa = ESPSAPayload(cryptoValues["espSPIr"]!!, algo)
        val tsi = TSiPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
        val tsr = TSrPayload("02000000080000280000ffff00000000000000000000000000000000ffffffffffffffffffffffffffffffff070000100000ffff00000000ffffffff".fromHex())
        val proxyNotify = NotifyPayload(50701, "fd7465726d6e7573000d6a146857bc23f516".fromHex())

        val msg = IKEMessage(exchangeType = 35, nextMsgId, initiatorSPI, responderSPI, isReply = true, isInitiator = false)
        val payloads = listOf(initialContact, idResp, auth, padding, fragments, sa, tsi, tsr, proxyNotify)
        msg.addPayloads(payloads)
        msg.encrypt(cryptoValues["skr"]!!, cryptoValues["skrSalt"]!!)
        nextMsgId += 1

        return msg.assemble()
    }

    private fun replyToHeartbeat(): ByteArray {
        val msg = IKEMessage(exchangeType = 37, nextMsgId, initiatorSPI, responderSPI, isReply = true, isInitiator = false)
        msg.encrypt(cryptoValues["skr"]!!, cryptoValues["skrSalt"]!!)
        nextMsgId += 1
        return msg.assemble()
    }

    private fun replyToLDMHello(identifier: Long): ByteArray {
        val msg = IKEMessage(exchangeType = 37, nextMsgId, initiatorSPI, responderSPI, isReply = true, isInitiator = weInitiate)
        val ldm = LinkDirectorMessage(identifier, listOf(LinkDirectorMessage.LdmTlv(1, byteArrayOf())))
        Logger.logIKE("assembled LDM: ${ldm.render().hex()}", 3)
        msg.addPayload(NotifyPayload(50702, ldm.render()))
        msg.encrypt(cryptoValues["skr"]!!, cryptoValues["skrSalt"]!!)
        nextMsgId += 1
        return msg.assemble()
    }

    private fun replyToLDMIpUpdate(identifier: Long): ByteArray {
        val msg = IKEMessage(exchangeType = 37, nextMsgId, initiatorSPI, responderSPI, isReply = true, isInitiator = weInitiate)
        val ldm = LinkDirectorMessage(identifier, listOf(LinkDirectorMessage.LdmTlv(3, RoutingManager.getLocalIPv4Address().address)))
        Logger.logIKE("assembled LDM: ${ldm.render().hex()}", 3)
        msg.addPayload(NotifyPayload(50702, ldm.render()))
        msg.encrypt(cryptoValues["skr"]!!, cryptoValues["skrSalt"]!!)
        nextMsgId += 1
        return msg.assemble()
    }

    private fun cryptoValuesUpdated() {
        // check if we have all required values to derive key material
        val requiredKeys = listOf("ni", "nr", "dhShared")
        if(requiredKeys.any { !cryptoValues.containsKey(it) })
            return

        val ci = initiatorSPI
        val cr = responderSPI
        val ni = cryptoValues["ni"]!!
        val nr = cryptoValues["nr"]!!
        val dh = cryptoValues["dhShared"]!!

        val skeyseed = Utils.HMAC(ni + nr, dh)

        //Logger.logIKE("SKEYSEED inputs ${(ni+nr).hex()} ${dh.hex()}", 10)
        //Logger.logIKE("SKEYSEED ${skeyseed.hex()}", 10)

        // compute SK_d (used for derivation of ESP keys) as well as IKE communication keys (auth/enc for initiator and responder each)
        val keystream = Utils.PRFplus(skeyseed, ni + nr + ci + cr, 264)

        // SK_d is the size of the hash function output (i.e. 512 in our case)
        val skd = keystream.sliceArray(0 until 64)

        // chacha/poly is AEAD so no explicit authentication keys are necessary, every key consists of the actual key (256 bit) as well as a 32 bit salt
        val ski = keystream.sliceArray(64 until 96)
        val skiSalt = keystream.sliceArray(96 until 100)
        val skr = keystream.sliceArray(100 until 132)
        val skrSalt = keystream.sliceArray(132 until 136)
        val skpi = keystream.sliceArray(136 until 200)
        val skpr = keystream.sliceArray(200 until 264)

        cryptoValues["skd"] = skd
        cryptoValues["ski"] = ski
        cryptoValues["skr"] = skr
        cryptoValues["skiSalt"] = skiSalt
        cryptoValues["skrSalt"] = skrSalt
        cryptoValues["skpi"] = skpi
        cryptoValues["skpr"] = skpr

        // ESP keys
        val keymat = Utils.PRFplus(skd, ni + nr, 128)
        cryptoValues["espKeyI"] = keymat.sliceArray(0 until 32)
        cryptoValues["espSaltI"] = keymat.sliceArray(32 until 36)
        cryptoValues["espKeyR"] = keymat.sliceArray(36 until 68)
        cryptoValues["espSaltR"] = keymat.sliceArray(68 until 72)

        Logger.logIKE("derived key material", 5)
        //Logger.logIKE(keystream.hex(), 4)

        sessionKeysReady = true

        createTunnelIfReady()
    }

    private fun createTunnelIfReady() {
        if(!sessionKeysReady || !cryptoValues.containsKey("espSPIi") || !cryptoValues.containsKey("espSPIr") || oobkey != null)
            return

        Logger.logIKE("IKE complete, setting up ESP tunnel", 0)
        transport.setupTunnel(
            cryptoValues["espSPIi"]!!,
            cryptoValues["espSPIr"]!!,
            cryptoValues["espKeyI"]!!,
            cryptoValues["espSaltI"]!!,
            cryptoValues["espKeyR"]!!,
            cryptoValues["espSaltR"]!!,
            dataProtectionClass == 3
        )
    }

    private fun authSignedBytes(forPeer: Boolean): ByteArray {
        return when {
            weInitiate && forPeer -> cryptoValues["peerSAinit"]!! + cryptoValues["ni"]!! + Utils.HMAC(cryptoValues["skpr"]!!, cryptoValues["IDr"]!!)
            weInitiate && !forPeer -> cryptoValues["ownSAinit"]!! + cryptoValues["nr"]!! + Utils.HMAC(cryptoValues["skpi"]!!, cryptoValues["IDi"]!!)
            !weInitiate && forPeer -> cryptoValues["peerSAinit"]!! + cryptoValues["nr"]!! + Utils.HMAC(cryptoValues["skpi"]!!, cryptoValues["IDi"]!!)
            else -> cryptoValues["ownSAinit"]!! + cryptoValues["ni"]!! + Utils.HMAC(cryptoValues["skpr"]!!, cryptoValues["IDr"]!!)
        }

    }

    private fun generateAuthSignature(): ByteArray {
        val signedBytes = authSignedBytes(forPeer = false)

        val context = if(weAreWatch) LongTermStorage.CONTEXT_WATCH else LongTermStorage.CONTEXT_PHONE

        val idA = LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A
        val idC = LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C
        val idD = LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D


        val key = when(dataProtectionClass) {
            1 -> LongTermStorage.getEd25519LocalPrivateKey(idA, context)
            3 -> LongTermStorage.getEd25519LocalPrivateKey(idC, context)
            else -> LongTermStorage.getEd25519LocalPrivateKey(idD, context)
        }

        val signer = Ed25519Signer()
        signer.init(true, key)
        signer.update(signedBytes, 0, signedBytes.size)

        return signer.generateSignature()
    }

    private fun generateAuthMAC(oobkey: ByteArray): ByteArray {
        val signedBytes = authSignedBytes(forPeer = false)

        val inner = Utils.HMAC(oobkey, "Key Pad for IKEv2".encodeToByteArray())
        val outer = Utils.HMAC(inner, signedBytes)

        return outer
    }

    private fun verifyAuthSignature(sig: ByteArray) {
        val signedBytes = authSignedBytes(forPeer = true)
        val context = if(weAreWatch) LongTermStorage.CONTEXT_WATCH else LongTermStorage.CONTEXT_PHONE
        val key = try {
            when(dataProtectionClass) {
                1 -> LongTermStorage.getEd25519RemotePublicKey(LongTermStorage.IKE_REMOTE_PUBLIC_A, context)
                3 -> LongTermStorage.getEd25519RemotePublicKey(LongTermStorage.IKE_REMOTE_PUBLIC_C, context)
                else -> LongTermStorage.getEd25519RemotePublicKey(LongTermStorage.IKE_REMOTE_PUBLIC_D, context)
            }
        } catch (e: Exception) {
            Logger.logIKE("We don't have IKE key material", 0)
            Logger.setError("missing keys")
            throw e
        }

        val verifier = Ed25519Signer()
        verifier.init(false, key)
        verifier.update(signedBytes, 0, signedBytes.size)
        val valid = verifier.verifySignature(sig)

        if(!valid) {
            Logger.logIKE("Auth signature verification failed", 0)
            throw Exception("Auth signature verification failed")
        }
    }

    private fun verifyAuthHMAC(sig: ByteArray, oobkey: ByteArray) {
        val signedBytes = authSignedBytes(forPeer = true)

        val inner = Utils.HMAC(oobkey, "Key Pad for IKEv2".encodeToByteArray())
        val outer = Utils.HMAC(inner, signedBytes)

        // not time safe!
        if(!outer.contentEquals(sig)) {
            Logger.logIKE("Auth signature verification failed", 0)
            throw Exception("Auth signature verification failed")
        }
    }
}

object IKEDefs {
    private val exchangeTypes = listOf("SA_INIT", "AUTH", "CHILD_SA", "INFO")
    private val payloadTypes = listOf("SA", "KEx", "IDinit", "IDresp", "CERT", "CERTREQ", "AUTH", "NONCE", "NOTIFY", "DELETE", "VENDOR", "TSi", "TSr", "ENC&AUTH", "CONFIG", "EAP")
    val notifyTypes = listOf("INITIAL_CONTACT", "SET_WINDOW_SIZE", "ADDITIONAL_TS_POSSIBLE", "IPCOMP_SUPPORTED", "NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP", "COOKIE", "USE_TRANSPORT_MODE", "HTTP_CERT_LOOKUP_SUPPORTED", "REKEY_SA", "ESP_TFC_PADDING_NOT_SUPPORTED", "NON_FIRST_FRAGMENTS_ALSO", "MOBIKE_SUPPORTED", "ADDITIONAL_IP4_ADDRESS", "ADDITIONAL_IP6_ADDRESS", "NO_ADDITIONAL_ADDRESSES", "UPDATE_SA_ADDRESSES", "COOKIE2", "NO_NATS_ALLOWED", "AUTH_LIFETIME", "MULTIPLE_AUTH_SUPPORTED", "ANOTHER_AUTH_FOLLOWS", "REDIRECT_SUPPORTED", "REDIRECT", "REDIRECTED_FROM", "TICKET_LT_OPAQUE", "TICKET_REQUEST", "TICKET_ACK", "TICKET_NACK", "TICKET_OPAQUE", "LINK_ID", "USE_WESP_MODE", "ROHC_SUPPORTED", "EAP_ONLY_AUTHENTICATION", "CHILDLESS_IKEV2_SUPPORTED", "QUICK_CRASH_DETECTION", "IKEV2_MESSAGE_ID_SYNC_SUPPORTED", "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED", "IKEV2_MESSAGE_ID_SYNC", "IPSEC_REPLAY_COUNTER_SYNC", "SECURE_PASSWORD_METHODS", "PSK_PERSIST", "PSK_CONFIRM", "ERX_SUPPORTED", "IFOM_CAPABILITY", "SENDER_REQUEST_ID", "IKEV2_FRAGMENTATION_SUPPORTED", "SIGNATURE_HASH_ALGORITHMS", "CLONE_IKE_SA_SUPPORTED", "CLONE_IKE_SA", "PUZZLE", "USE_PPK", "PPK_IDENTITY", "NO_PPK_AUTH", "INTERMEDIATE_EXCHANGE_SUPPORTED", "IP4_ALLOWED", "IP6_ALLOWED")
    private val errorTypes = listOf("reserved", "UNSUPPORTED_CRITICAL_PAYLOAD", "reserved", "reserved", "INVALID_IKE_SPI", "INVALID_MAJOR_VERSION", "reserved", "INVALID_SYNTAX", "reserved", "INVALID_MESSAGE_ID", "reserved", "INVALID_SPI", "reserved", "reserved", "NO_PROPOSAL_CHOSEN", "reserved", "reserved", "INVALID_KE_PAYLOAD", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "AUTHENTICATION_FAILED", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "SINGLE_PAIR_REQUIRED", "NO_ADDITIONAL_SAS", "INTERNAL_ADDRESS_FAILURE", "FAILED_CP_REQUIRED", "TS_UNACCEPTABLE", "INVALID_SELECTORS", "TEMPORARY_FAILURE", "CHILD_SA_NOT_FOUND", "INVALID_GROUP_ID", "AUTHORIZATION_FAILURE", "STATE_NOT_FOUND", "TS_MAX_QUEUE")
    val privateNotifyTypes = mapOf(
        48601 to "Encrypted prelude",
        48602 to "Remote terminus version",
        48603 to "Remote device name",
        48604 to "Remote build version",
        48605 to "Remote device flags", // observed: zero
        48606 to "Remote device type", // 01 iPhone, 02 Watch
        48607 to "Remote IDS device ID", // ASCII UUID
        48701 to "unknown 48701 - initiate session after unlock?", // observed from iPhone: 80
        50000 to "unknown 50000 - seq per TC?",
        50351 to "Device Identity Data", // UUID + ccec25519pubkey, observed: 8269c358be1a479b8078d5ed98fad1e652c89e71807055d54f2161f639de2c9b625bf32dfdb4914168afe14822c1cd38
        50352 to "Request Identity Data",
        50401 to "RemoteClassDKeysEncryptedWithIDS",
        50402 to "RemoteClassCKeysEncryptedWithIDS",
        50403 to "RemoteClassAKeysEncryptedWithIDS",
        50410 to "InitiatorLocalPublicClassDKeysEncryptedWithIDS",
        50411 to "InitiatorLocalPublicClassDKeys",
        50412 to "InitiatorLocalPublicClassCKeys",
        50413 to "InitiatorLocalPublicClassAKeys",
        50701 to "ProxyNotifyPayload?",
        50702 to "LinkDirectorMessage",
        50801 to "InnerAddressInitiatorClassD",
        50802 to "InnerAddressResponderClassD",
        50811 to "InnerAddressInitiatorClassC",
        50812 to "InnerAddressResponderClassC",
        50901 to "suspendWhenReady?",
        51401 to "Always-On WiFi support",
        51501 to "IsAltAccountDevice"
    )


    fun errorToString(type: Int): String {
        return if(type < errorTypes.size)
            errorTypes[type]
        else
            "unknown error: $type"
    }

    fun exchangeType(type: Byte): String {
        return exchangeTypes[type - 34]
    }

    fun nextPayload(type: Int): String {
        return if(type == 0x0)
            "None"
        else
            payloadTypes[type - 33]
    }
}