package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromBytes
import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.bitmage.untilIndex
import net.rec0de.android.watchwitch.decoders.protobuf.ProtoBuf
import net.rec0de.android.watchwitch.transport.RoutingManager
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.nio.ByteBuffer
import java.util.Date
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


object Utils {
    fun getLocalIP(): String = RoutingManager.getLocalIPv4Address().hostAddress!!

    fun HMAC(k: ByteArray, v: ByteArray): ByteArray {
        //Logger.logIKE("HMAC(key ${k.hex()}) for data ${v.hex()}", 3)
        val hmac = org.bouncycastle.crypto.macs.HMac(SHA512Digest())
        hmac.init(KeyParameter(k))
        val digest = ByteArray(hmac.macSize)
        hmac.update(v, 0, v.size)
        hmac.doFinal(digest, 0)
        //Logger.logIKE(digest.hex(), 3)
        return digest
    }

    fun PRFplus(key: ByteArray, data: ByteArray, length: Int): ByteArray {
        var keystream = byteArrayOf()
        var counter = 1

        var lastblock = HMAC(key, data + byteArrayOf(counter.toByte()))
        keystream += lastblock
        counter += 1

        while(keystream.size < length) {
            lastblock = HMAC(key, lastblock + data + byteArrayOf(counter.toByte()))
            keystream += lastblock
            counter += 1
        }

        return keystream
    }

    fun chachaPolyDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val chacha = ChaCha20Poly1305()
        val params = AEADParameters(KeyParameter(key), 16*8, nonce, aad)
        chacha.init(false, params)

        val plaintext = ByteArray(chacha.getOutputSize(ciphertext.size))
        val finalOffset = chacha.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
        chacha.doFinal(plaintext, finalOffset)

        return plaintext
    }

    fun chachaPolyEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val chacha = ChaCha20Poly1305()
        val params = AEADParameters(KeyParameter(key), 16*8, nonce, aad)
        chacha.init(true, params)

        val ciphertext = ByteArray(chacha.getOutputSize(plaintext.size))
        val finalOffset = chacha.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        chacha.doFinal(ciphertext, finalOffset)

        return ciphertext
    }

    fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        // Validate inputs
        require(nonce.size == 12) { "Nonce must be 12 bytes, got ${nonce.hex()}" }

        // Initialize cipher for decryption
        val key = SecretKeySpec(key, "AES")
        val gcmParams = GCMParameterSpec(16*8, nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParams)


        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }

        return cipher.doFinal(ciphertext)
    }

    fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        // Validate inputs
        require(nonce.size == 12) { "Nonce must be 12 bytes, got ${nonce.hex()}" }

        // Initialize cipher for decryption
        val key = SecretKeySpec(key, "AES")
        val gcmParams = GCMParameterSpec(16*8, nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams)


        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }

        return cipher.doFinal(plaintext)
    }

    fun uuidFromBytes(bytes: ByteArray): UUID {
        if(bytes.size != 16)
            throw Exception("Trying to build UUID from ${bytes.size} bytes, expected 16")

        val a = bytes.sliceArray(0 until 4).hex()
        val b = bytes.sliceArray(4 until 6).hex()
        val c = bytes.sliceArray(6 until 8).hex()
        val d = bytes.sliceArray(8 until 10).hex()
        val e = bytes.sliceArray(10 until 16).hex()
        return UUID.fromString("$a-$b-$c-$d-$e")
    }

    fun uuidToBytes(uuid: UUID): ByteArray {
        val buf = ByteBuffer.allocate(16)
        buf.putLong(uuid.mostSignificantBits)
        buf.putLong(uuid.leastSignificantBits)
        return buf.array()
    }

    fun dateFromAppleTimestamp(timestamp: Double): Date {
        // NSDate timestamps encode time as seconds since Jan 01 2001 with millisecond precision as doubles
        return Date((timestamp*1000).toLong() + 978307200000)
    }

    /**
     * Computes IP checksum of concatenated parts. WARNING: pads each part separately to even length!
     * This may well cause subtle bugs but helps us not copy bytearrays around that we know to be even
     **/
    fun ipChecksum(vararg parts: ByteArray): Int {
        var csum: UInt = 0u

        parts.forEach { buf ->
            for (i in 0 until buf.size/2) {
                csum += (buf[i*2].toUByte().toUInt() * 256u) + buf[i*2+1].toUByte()
            }
            // this should be identical to padding parts to even length with zero bytes
            if(buf.size % 2 == 1)
                csum += buf.last().toUShort() * 256u
        }

        csum += csum shr 16
        csum = (csum and 0xffffu) xor 0xffffu

        //println("checksum of ${parts.joinToString { it.hex() }} is ${csum.toString(16)}")

        return csum.toInt()
    }
}

object Log {
    fun d(tag: String, msg: String) {
        println("\u001b[90m[$tag] $msg\u001b[0m")
    }

    fun w(tag: String, msg: String) {
        println("[$tag] $msg")
    }

    fun big(tag: String, msg: String) {
        println("\u001b[1m[$tag] $msg\u001b[0m")
    }
}

open class ParseCompanion {
    protected var parseOffset = 0

    protected fun readBytes(bytes: ByteArray, length: Int): ByteArray {
        val sliced = bytes.sliceArray(parseOffset until parseOffset + length)
        parseOffset += length
        return sliced
    }

    protected fun readLengthPrefixedString(bytes: ByteArray, sizePrefixLen: Int): String? {
        val len = readInt(bytes, sizePrefixLen)
        return if(len == 0) null else readString(bytes, len)
    }

    protected fun readString(bytes: ByteArray, size: Int): String {
        val str = bytes.sliceArray(parseOffset until parseOffset +size).toString(Charsets.UTF_8)
        parseOffset += size
        return str
    }

    protected fun readInt(bytes: ByteArray, size: Int, explicitlySigned: Boolean = false, byteOrder: ByteOrder = ByteOrder.BIG): Int {
        val int = Int.fromBytes(bytes.sliceArray(parseOffset until parseOffset +size), byteOrder, explicitlySigned)
        parseOffset += size
        return int
    }

    protected fun readLong(bytes: ByteArray, size: Int, byteOrder: ByteOrder = ByteOrder.BIG): Long {
        val int = Long.fromBytes(bytes.sliceArray(parseOffset until parseOffset +size), byteOrder)
        parseOffset += size
        return int
    }

    protected fun readUInt(bytes: ByteArray, size: Int, byteOrder: ByteOrder = ByteOrder.BIG): UInt {
        val int = UInt.fromBytes(bytes.sliceArray(parseOffset until parseOffset +size), byteOrder)
        parseOffset += size
        return int
    }

    protected fun readULong(bytes: ByteArray, size: Int, byteOrder: ByteOrder = ByteOrder.BIG): ULong {
        val int = ULong.fromBytes(bytes.sliceArray(parseOffset until parseOffset +size), byteOrder)
        parseOffset += size
        return int
    }
}

abstract class PBParsable<TargetClass> {
    abstract fun fromSafePB(pb: ProtoBuf): TargetClass
    fun fromPB(pb: ProtoBuf?): TargetClass? {
        if(pb == null)
            return null
        return fromSafePB(pb)
    }
}

fun Date.toAppleTimestamp(): Double {
    // NSDate timestamps encode time as seconds since Jan 01 2001 with millisecond precision as doubles
    val canonicalTimestamp = this.time
    return (canonicalTimestamp - 978307200000).toDouble() / 1000
}

fun Date.toCanonicalTimestamp(): Double {
    return this.time.toDouble() / 1000
}

// based on https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/ with specific algorithm choices baked in
object HPKE {
    fun decrypt(ciphertext: ByteArray, privateKey: ByteArray, psk: ByteArray, pskID: ByteArray, aad: ByteArray): ByteArray {
        val encapKey = ciphertext.untilIndex(32)
        val aeadCipher = ciphertext.fromIndex(32)
        val info = "Encrypted Identifier for IKEv2".encodeToByteArray()

        val privKeyParams = X25519PrivateKeyParameters(privateKey)
        val pubKeyParams = privKeyParams.generatePublicKey()

        val keyPair = AsymmetricCipherKeyPair(pubKeyParams, privKeyParams)

        val hpke = HPKE(
            HPKE.mode_psk,
            HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA512,
            HPKE.aead_AES_GCM256
        ).setupPSKR(encapKey, keyPair, info, psk, pskID)

        return hpke.open(aad, aeadCipher)
    }

    fun encrypt(plaintext: ByteArray, publicKey: ByteArray, psk: ByteArray, pskID: ByteArray, aad: ByteArray): ByteArray {
        val info = "Encrypted Identifier for IKEv2".encodeToByteArray()
        val pubKeyParams = X25519PublicKeyParameters(publicKey)

        //Log.d("HPKE", "psk: ${psk.hex()} pskid: ${pskID.hex()} aad: ${aad.hex()}")
        //Log.d("HPKE", "public ${publicKey.hex()} plain: ${plaintext.hex()}")

        val hpke = HPKE(
            HPKE.mode_psk,
            HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA512,
            HPKE.aead_AES_GCM256
        ).SetupPSKS(pubKeyParams, info, psk, pskID)

        val encapKey = hpke.encapsulation
        val sealed = hpke.seal(aad, plaintext)
        return encapKey+sealed
    }
}