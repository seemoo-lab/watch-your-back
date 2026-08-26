package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.fromIndex
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


// adapted from https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/crypto/KeyStoreHelper.java

object KeyStoreHelper {
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val INTERNAL_KEY_ALIAS = "WatchWitchSecret"

    // on android, we'd store this in the keystore persistently
    // here, we'll just generate everything on the fly
    private val sealingSecretKey = generateSealingKey()

    fun generateSealingKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(128)
        return keyGen.generateKey()
    }

    fun seal(input: ByteArray, aad: String): SealedData {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, sealingSecretKey)
        cipher.updateAAD(aad.encodeToByteArray())
        val iv = cipher.iv
        val data = cipher.doFinal(input)
        return SealedData(iv, data)
    }

    fun unseal(sealedData: SealedData, aad: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, sealingSecretKey, GCMParameterSpec(128, sealedData.iv))
        cipher.updateAAD(aad.encodeToByteArray())
        return cipher.doFinal(sealedData.data)
    }

    private fun aovercEcdsaSign(message: ByteArray, keyContext: String): ByteArray {
        // i hear that keystore operations can be slow, but we'll just try it
        // perhaps it makes sense to cache the unsealed private key on app start
        val sealed = LongTermStorage.getBytes(LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_A, keyContext)!!
        val keyIdentifier = "$keyContext!${LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_A}"
        val keyBytes = unseal(SealedData.fromBytes(sealed), keyIdentifier)
        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val params = ECNamedCurveSpec("secp256r1", spec.curve, spec.g, spec.n)
        val key = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(keyBytes), params))

        return Signature.getInstance("SHA1withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
    }

    fun aovercEcdsaSignAsPhone(message: ByteArray) = aovercEcdsaSign(message, LongTermStorage.CONTEXT_PHONE)
    fun aovercEcdsaSignAsWatch(message: ByteArray) = aovercEcdsaSign(message, LongTermStorage.CONTEXT_WATCH)

    private fun aovercRsaDecrypt(ciphertext: ByteArray, keyContext: String): ByteArray {
        // i hear that keystore operations can be slow, but we'll just try it
        // perhaps it makes sense to cache the unsealed private key on app start
        val sealed = LongTermStorage.getBytes(LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_A, keyContext)!!
        val keyIdentifier = "$keyContext!${LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_A}"
        val keyBytes = unseal(SealedData.fromBytes(sealed), keyIdentifier)
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyBytes))

        val decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING")
        val oaepParams = OAEPParameterSpec("SHA1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        decryptCipher.init(Cipher.DECRYPT_MODE, key, oaepParams)
        return decryptCipher.doFinal(ciphertext)
    }

    fun aovercRsaDecryptAsPhone(message: ByteArray) = aovercRsaDecrypt(message, LongTermStorage.CONTEXT_PHONE)
    fun aovercRsaDecryptAsWatch(message: ByteArray) = aovercRsaDecrypt(message, LongTermStorage.CONTEXT_WATCH)

    fun aovercRsaPubkey(dpc: Int, keyContext: String): ByteArray {
        val keyStorageLocation = when(dpc) {
            1 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_A
            3 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_C
            4 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_D
            else -> throw Exception("unsupported data protection class: $dpc")
        }
        val keyIdentifier = "$keyContext!$keyStorageLocation"
        val sealed = LongTermStorage.getBytes(keyStorageLocation, keyContext)!!
        val privateKey = unseal(SealedData.fromBytes(sealed), keyIdentifier)

        val kf = KeyFactory.getInstance("RSA")
        val privateParsed = kf.generatePrivate(PKCS8EncodedKeySpec(privateKey))
        val privSpec = kf.getKeySpec(privateParsed, RSAPrivateKeySpec::class.java)
        val keySpec = RSAPublicKeySpec(privSpec.modulus, BigInteger.valueOf(65537))
        val pubKey = kf.generatePublic(keySpec)

        // java can be incredibly annoying about key encodings
        // these are the magic words to get it to output PKCS#1
        val rsaPublicBytes = SubjectPublicKeyInfo.getInstance(pubKey.encoded).parsePublicKey().encoded
        return rsaPublicBytes
    }

    fun aovercEcdsaPubkey(dpc: Int, keyContext: String): ByteArray {
        val keyStorageLocation = when(dpc) {
            1 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_A
            3 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_C
            4 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_D
            else -> throw Exception("unsupported data protection class: $dpc")
        }
        val keyIdentifier = "$keyContext!$keyStorageLocation"
        val sealed = LongTermStorage.getBytes(keyStorageLocation, keyContext)!!
        val privateKey = unseal(SealedData.fromBytes(sealed), keyIdentifier)

        val spec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val params = ECNamedCurveSpec("secp256r1", spec.curve, spec.g, spec.n)
        val privateKeyEc = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(privateKey), params))

        // derive public key by multiplying with generator
        val q: ECPoint = spec.g.multiply((privateKeyEc as ECPrivateKey).s).normalize()
        return "04".fromHex() + q.affineXCoord.encoded + q.affineYCoord.encoded
    }

    fun enrollAovercRsaPrivateKey(key: PrivateKey, keyContext: String, dpc: Int) {

        val keyStorageLocation = when(dpc) {
            1 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_A
            3 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_C
            4 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_RSA_D
            else -> throw Exception("unsupported data protection class: $dpc")
        }

        // Apple uses severely nonstandard RSA key sizes which are not supported by the Android keystore 🙄
        // we'll do our best by storing them client side as sealed data the same way we store health data
        val keyIdentifier = "$keyContext!$keyStorageLocation"
        val sealed = seal(key.encoded, keyIdentifier)
        LongTermStorage.setBytes(keyStorageLocation, keyContext, sealed.toBytes())
        //Logger.log("Enrolled RSA private key (sealed-at-rest)", 1)
    }

    fun enrollAovercEcdsaPrivateKey(key: ECPrivateKey, keyContext: String, dpc: Int) {
        val keyStorageLocation = when(dpc) {
            1 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_A
            3 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_C
            4 -> LongTermStorage.MP_LOCAL_SEALED_PRIVATE_ECDSA_D
            else -> throw Exception("unsupported data protection class: $dpc")
        }

        // same here: we can't quite use the nice keystore interface to generate signatures in the secure hardware
        // because Apple uses SHA1 for their signatures and the keystore only supports SHA256
        val keyIdentifier = "$keyContext!$keyStorageLocation"
        val sealed = seal(key.s.toByteArray(), keyIdentifier)
        LongTermStorage.setBytes(keyStorageLocation, keyContext, sealed.toBytes())
        //Logger.log("Enrolled ECDSA private key (sealed-at-rest)", 1)
    }





    class SealedData(val iv: ByteArray, val data: ByteArray) {
        companion object {
            fun fromBytes(bytes: ByteArray): SealedData {
                val ivLen = bytes[0].toInt()
                val remaining = bytes.fromIndex(1)
                val iv = remaining.sliceArray(0 until ivLen)
                val data = remaining.fromIndex(ivLen)
                return SealedData(iv, data)
            }
        }

        fun toBytes(): ByteArray {
            val buf = ByteBuffer.allocate(iv.size+data.size+1) // store IV with 1 byte length prefix
            buf.put(iv.size.toByte())
            buf.put(iv)
            buf.put(data)
            return buf.array()
        }
    }
}