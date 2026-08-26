package net.rec0de.android.watchwitch.devices

import net.rec0de.android.watchwitch.KeyStoreHelper
import net.rec0de.android.watchwitch.LongTermStorage
import net.rec0de.android.watchwitch.Utils
import net.rec0de.android.watchwitch.bitmage.fromHex
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.UUID

interface WatchData {
    var NAME: String
    val HW_VERSION: String
    val OS_VERSION: String
    val OS_NAME: String
    val BUILD: String
    val MODEL_NUMBER: String
    val DEVICE_ID: String
    val TERMINUS_VERSION: ByteArray

    val protocolVersion: Int
    val compatMinProtocolVersion: Int
    val compatMaxProtocolVersion: Int
    val serviceMinimumCompatibilityVersion: Int
    val capabilityFlags: Int

    val useX448: Boolean
    val espUseAESGCM: Boolean
    val useDeviceIdentity: Boolean
    val useNewNotifies: Boolean
}

object Watch5_1_wos7: WatchData {
    override var NAME = "Apple Watch"
    override val HW_VERSION = "Watch5,1"
    override val OS_VERSION = "7.3.3"
    override val OS_NAME = "Watch OS"
    override val BUILD = "18S830"
    override val MODEL_NUMBER = "MWV82"
    override val DEVICE_ID = UUID.randomUUID().toString().uppercase() //"BD7D0F80-C849-411C-94B4-B4D3531CDA33"
    override val TERMINUS_VERSION = byteArrayOf(0x00, 0x0c)

    override val protocolVersion = 15
    override val compatMinProtocolVersion = 0
    override val compatMaxProtocolVersion = 15
    override val serviceMinimumCompatibilityVersion = 10
    override val capabilityFlags = 0x3ff

    override val useX448 = false
    override val espUseAESGCM = false
    override val useDeviceIdentity = false
    override val useNewNotifies = false
}

object Watch5_1_wos9: WatchData {
    override var NAME = "Apple Watch"
    override val HW_VERSION = "Watch5,1"
    override val OS_VERSION = "9.6.4"
    override val OS_NAME = "Watch OS"
    override val BUILD = "20U512"
    override val MODEL_NUMBER = "MWV82"
    override val DEVICE_ID = UUID.randomUUID().toString().uppercase()
    override val TERMINUS_VERSION = byteArrayOf(0x00, 0x0c)

    override val protocolVersion = 18 // was 15
    override val compatMinProtocolVersion = 0
    override val compatMaxProtocolVersion = 18 // was 15
    override val serviceMinimumCompatibilityVersion = 15 // was 10
    override val capabilityFlags = 0x3ff

    override val useX448: Boolean = false
    override val espUseAESGCM = false
    override val useDeviceIdentity = false
    override val useNewNotifies = false
}

object Watch7_1_wos10: WatchData {
    override var NAME = "Apple Watch"
    override val HW_VERSION = "Watch7,1"
    override val OS_VERSION = "10.6.1"
    override val OS_NAME = "Watch OS"
    override val BUILD = "21U580"
    override val MODEL_NUMBER = "MWV82"
    override val DEVICE_ID = UUID.randomUUID().toString().uppercase() //"A78002CA-7C1E-45C8-B212-738ACD81A77D"
    override val TERMINUS_VERSION = byteArrayOf(0x00, 0x0c)

    override val protocolVersion = 22
    override val compatMinProtocolVersion = 0
    override val compatMaxProtocolVersion = 22
    override val serviceMinimumCompatibilityVersion = 17
    override val capabilityFlags = 0x3ff

    override val useX448: Boolean = false
    override val espUseAESGCM = false
    override val useDeviceIdentity = false
    override val useNewNotifies = false
}

object Watch7_1_wos11: WatchData {
    override var NAME = "Apple Watch"
    override val HW_VERSION = "Watch7,1"
    override val OS_VERSION = "11.5"
    override val OS_NAME = "Watch OS"
    override val BUILD = "22T572"
    override val MODEL_NUMBER = "MWV82"
    override val DEVICE_ID = UUID.randomUUID().toString().uppercase()
    override val TERMINUS_VERSION = byteArrayOf(0x00, 0x16)
    override val protocolVersion = 22
    override val compatMinProtocolVersion = 0
    override val compatMaxProtocolVersion = 24
    override val serviceMinimumCompatibilityVersion = 17
    override val capabilityFlags = 0x3ff

    override val useX448: Boolean = true
    override val espUseAESGCM = true
    override val useDeviceIdentity = true
    override val useNewNotifies = true
}

object Watch6_3_wos10: WatchData {
    // "<Watch6,3> <Watch OS;10.4;21T216> <com.apple.AuthKit/1 (com.apple.nanobuddy/1.0)>"
    // "_uniqueDeviceIdentifier"="00008301-A894ECC60CC2402E"
    // "_provisioningDeviceIdentifier"="00008301-A894ECC60CC2402E"
    override var NAME = "Apple Watch"
    override val HW_VERSION = "Watch6,3"
    override val OS_VERSION = "10.4"
    override val OS_NAME = "Watch OS"
    override val BUILD = "21T216"
    override val MODEL_NUMBER = "M06R3"
    override val DEVICE_ID = "A78002CA-7C1E-45C8-B212-738ACD81A77D"
    override val TERMINUS_VERSION = byteArrayOf(0x00, 0x0c)
    override val protocolVersion = 22
    override val compatMinProtocolVersion = 0
    override val compatMaxProtocolVersion = 22
    override val serviceMinimumCompatibilityVersion = 17
    override val capabilityFlags = 0x3ff

    override val useX448: Boolean = false
    override val espUseAESGCM = false
    override val useDeviceIdentity = false
    override val useNewNotifies = false
}

object Watch {

    private var data: WatchData = Watch5_1_wos7

    var NAME = ""
        get() = field.ifEmpty { data.NAME }

    val HW_VERSION
        get() = data.HW_VERSION
    val OS_VERSION
        get() = data.OS_VERSION
    val OS_NAME
        get() = data.OS_NAME
    val BUILD
        get() = data.BUILD
    val MODEL_NUMBER
        get() = data.MODEL_NUMBER
    val DEVICE_ID
        get() = data.DEVICE_ID
    val TERMINUS_VERSION
        get() = data.TERMINUS_VERSION
    val ALLOY_PROTOCOL_VERSION
        get() = data.protocolVersion
    val ALLOY_MIN_PROTOCOL_VERSION
        get() = data.compatMinProtocolVersion
    val ALLOY_MAX_PROTOCOL_VERSION
        get() = data.compatMaxProtocolVersion
    val SERVICE_MIN_VERSION
        get() = data.serviceMinimumCompatibilityVersion
    val CAPABILITY_FLAGS
        get() = data.capabilityFlags
    val useX448
        get() = data.useX448
    val espUseAESGCM
        get() = data.espUseAESGCM
    val useDeviceIdentity
        get() = data.useDeviceIdentity
    val useNewNotifies
        get() = data.useNewNotifies


    fun setModel(watch: WatchData) {
        data = watch
    }

    fun generateKeys() {
        val watchctx = LongTermStorage.CONTEXT_WATCH

        if(LongTermStorage.getBytes(LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_A, watchctx) == null) {
            //Logger.log("Generating local MP keys", 0)
            generateMessageProtectionKeys(1) // class A
            generateMessageProtectionKeys(3) // class C
            generateMessageProtectionKeys(4) // class D
        }
        if(LongTermStorage.getBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A, watchctx) == null) {
            //Logger.log("Generating local IKE keys", 0)

            val random = SecureRandom()
            val kpg = Ed25519KeyPairGenerator()
            kpg.init(Ed25519KeyGenerationParameters(random))

            val identitfyKey = kpg.generateKeyPair()
            val idPrivate = identitfyKey.private as Ed25519PrivateKeyParameters
            val idPublic = identitfyKey.public as Ed25519PublicKeyParameters
            LongTermStorage.setBytes(LongTermStorage.LOCAL_DEVICE_IDENTITY, watchctx, Utils.uuidToBytes(UUID.randomUUID()))
            LongTermStorage.setBytes(LongTermStorage.LOCAL_DEVICE_IDENTITY_PRIVATE_KEY, watchctx, idPrivate.encoded)

            val a = kpg.generateKeyPair()
            val privateA = a.private as Ed25519PrivateKeyParameters
            val publicA = a.public as Ed25519PublicKeyParameters

            var keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A}"
            var sealed = KeyStoreHelper.seal(privateA.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A, watchctx, sealed)

            val c = kpg.generateKeyPair()
            val privateC = c.private as Ed25519PrivateKeyParameters
            val publicC = c.public as Ed25519PublicKeyParameters

            keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C}"
            sealed = KeyStoreHelper.seal(privateC.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C, watchctx, sealed)

            val d = kpg.generateKeyPair()
            val privateD = d.private as Ed25519PrivateKeyParameters
            val publicD = d.public as Ed25519PublicKeyParameters

            keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D}"
            sealed = KeyStoreHelper.seal(privateD.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D, watchctx, sealed)

            // second half of exchanged pubkeys, suspected separate WiFi creds??
            val a2 = kpg.generateKeyPair()
            val privateA2 = a2.private as Ed25519PrivateKeyParameters
            val publicA2 = a2.public as Ed25519PublicKeyParameters

            keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A2}"
            sealed = KeyStoreHelper.seal(privateA2.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_A2, watchctx, sealed)

            val c2 = kpg.generateKeyPair()
            val privateC2 = c2.private as Ed25519PrivateKeyParameters
            val publicC2 = c2.public as Ed25519PublicKeyParameters

            keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C2}"
            sealed = KeyStoreHelper.seal(privateC2.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_C2, watchctx, sealed)

            val d2 = kpg.generateKeyPair()
            val privateD2 = d2.private as Ed25519PrivateKeyParameters
            val publicD2 = d2.public as Ed25519PublicKeyParameters

            keyIdentifier = "$watchctx!${LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D2}"
            sealed = KeyStoreHelper.seal(privateD2.encoded, keyIdentifier).toBytes()
            LongTermStorage.setBytes(LongTermStorage.IKE_LOCAL_SEALED_PRIVATE_D2, watchctx, sealed)
        }
    }

    private fun generateMessageProtectionKeys(dpc: Int) {
        //Logger.log("Generating local MP keys for class $dpc", 0)
        // ECDSA keys
        val ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
        generator.initialize(ecSpec, SecureRandom())
        val watchEcdsaKeys: KeyPair = generator.generateKeyPair()

        // RSA keys
        val rsaGen = KeyPairGenerator.getInstance("RSA")
        rsaGen.initialize(1280)
        val watchRsaKeys = rsaGen.generateKeyPair()

        KeyStoreHelper.enrollAovercEcdsaPrivateKey(watchEcdsaKeys.private as java.security.interfaces.ECPrivateKey, LongTermStorage.CONTEXT_WATCH, dpc)
        KeyStoreHelper.enrollAovercRsaPrivateKey(watchRsaKeys.private, LongTermStorage.CONTEXT_WATCH, dpc)
    }

    private fun ecdsaGetPublicBytes(ecPublicKey: ECPublicKey): ByteArray {
        val ecPoint = ecPublicKey.q
        return "04".fromHex() + ecPoint.affineXCoord.encoded + ecPoint.affineYCoord.encoded
    }
}