package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.hex
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.util.UUID

object LongTermStorage {
    private val storage = mutableMapOf<String, String>()

    const val appID = "net.rec0de.android.watchwitch"

    const val CONTEXT_WATCH = "watch"
    const val CONTEXT_PHONE = "phone"

    const val IKE_REMOTE_PUBLIC_A = "ike.remote.a.public"
    const val IKE_REMOTE_PUBLIC_C = "ike.remote.c.public"
    const val IKE_REMOTE_PUBLIC_D = "ike.remote.d.public"

    const val IKE_LOCAL_SEALED_PRIVATE_A = "ike.sealed.local.a.private"
    const val IKE_LOCAL_SEALED_PRIVATE_C = "ike.sealed.local.c.private"
    const val IKE_LOCAL_SEALED_PRIVATE_D = "ike.sealed.local.d.private"
    const val IKE_LOCAL_SEALED_PRIVATE_A2 = "ike.sealed.local.a.private.2"
    const val IKE_LOCAL_SEALED_PRIVATE_C2 = "ike.sealed.local.c.private.2"
    const val IKE_LOCAL_SEALED_PRIVATE_D2 = "ike.sealed.local.d.private.2"

    const val MP_REMOTE_PUBLIC_RSA_A          = "mp.remote.a.rsa.public"
    const val MP_REMOTE_PUBLIC_ECDSA_A        = "mp.remote.a.ecdsa.public"
    const val MP_LOCAL_SEALED_PRIVATE_RSA_A   = "mp.sealed.local.a.rsa.private"
    const val MP_LOCAL_SEALED_PRIVATE_ECDSA_A = "mp.sealed.local.a.ecdsa.private"

    const val MP_REMOTE_PUBLIC_RSA_C          = "mp.remote.c.rsa.public"
    const val MP_REMOTE_PUBLIC_ECDSA_C        = "mp.remote.c.ecdsa.public"
    const val MP_LOCAL_SEALED_PRIVATE_RSA_C   = "mp.sealed.local.c.rsa.private"
    const val MP_LOCAL_SEALED_PRIVATE_ECDSA_C = "mp.sealed.local.c.ecdsa.private"

    const val MP_REMOTE_PUBLIC_RSA_D          = "mp.remote.d.rsa.public"
    const val MP_REMOTE_PUBLIC_ECDSA_D        = "mp.remote.d.ecdsa.public"
    const val MP_LOCAL_SEALED_PRIVATE_RSA_D   = "mp.sealed.local.d.rsa.private"
    const val MP_LOCAL_SEALED_PRIVATE_ECDSA_D = "mp.sealed.local.d.ecdsa.private"

    const val LOCAL_ADDRESS_CLASS_C = "local.c.address"
    const val LOCAL_ADDRESS_CLASS_D = "local.d.address"
    const val REMOTE_ADDRESS_CLASS_C = "remote.c.address"
    const val REMOTE_ADDRESS_CLASS_D = "remote.d.address"

    const val LOCAL_DEVICE_IDENTITY = "local.deviceid.uuid"
    const val LOCAL_DEVICE_IDENTITY_PRIVATE_KEY = "local.deviceid.key.private"
    const val REMOTE_DEVICE_IDENTITY = "remote.deviceid.uuid"
    const val REMOTE_DEVICE_IDENTITY_PUBLIC_KEY = "remote.deviceid.key.public"


    private const val KEY_TRANSIT_SECRET = "keyreceiver.sharedsecret"
    private const val ENCRYPTED_DB_SECRET = "database.encryptedsecret"

    private const val NOTIFICATION_ACCESS_CONSENT = "notification.consent"

    private val addresstypes = listOf(LOCAL_ADDRESS_CLASS_C, LOCAL_ADDRESS_CLASS_D, REMOTE_ADDRESS_CLASS_C, REMOTE_ADDRESS_CLASS_D)

    fun getUTUNDeviceID(): UUID? {
        val str = storage.getOrDefault("misc.utun.localuuid", null)
        return if(str == null) null else UUID.fromString(str)
    }

    fun setUTUNDeviceID(uuid: String) {
        storage["misc.utun.localuuid"] = uuid
    }

    fun getEd25519RemotePublicKey(type: String, ctx: String): Ed25519PublicKeyParameters {
        val bytes = getBytes(type, ctx)
        if(bytes == null) {
            Logger.setError("uninitialized keys")
            throw Exception("Trying to get uninitialized key: $type")
        }
        return Ed25519PublicKeyParameters(bytes)
    }

    fun getEd25519LocalPrivateKey(type: String, ctx: String): Ed25519PrivateKeyParameters {
        val bytes = getBytes(type, ctx)
        if(bytes == null) {
            Logger.setError("uninitialized keys")
            throw Exception("Trying to get uninitialized key: $type")
        }
        val keyIdentifier = "$ctx!$type"
        val unsealed = KeyStoreHelper.unseal(KeyStoreHelper.SealedData.fromBytes(bytes), keyIdentifier)
        return Ed25519PrivateKeyParameters(unsealed)
    }

    fun gotEd25519Key(type: String, ctx: String): Boolean {
        val bytes = getBytes(type, ctx)
        return bytes != null
    }

    fun getAddress(name: String, ctx: String): String? {
        if (!addresstypes.contains(name))
            throw Exception("trying to get address for invalid type $name")
        return storage.getOrDefault("$ctx!$name", null)
    }

    fun setAddress(name: String, ctx: String, value: String) {
        if (!addresstypes.contains(name))
            throw Exception("trying to set address for invalid type $name")
        storage["$ctx!$name"] = value
    }

    fun getBytes(name: String, ctx: String): ByteArray? {
        return storage.getOrDefault("$ctx!$name", null)?.fromHex()
    }

    fun setBytes(name: String, ctx: String, value: ByteArray) {
        //println("storing bytes at $ctx!$name")
        storage["$ctx!$name"] = value.hex()
    }
}