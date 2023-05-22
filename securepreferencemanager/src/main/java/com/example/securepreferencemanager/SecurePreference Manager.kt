package com.example.securepreferencemanager

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.preference.PreferenceManager
import java.io.UnsupportedEncodingException
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


/**
 * Secure Preference Manager which will use for storing the values of key in encrypted form
 *
 */

class SecurePreferenceManager(context: Context, key: String, salt: String, byteArray: Int) {

    /**
     * Initialise Default Shared Preference
     *
     */
    private var sharedPreferences: SharedPreferences =
        PreferenceManager.getDefaultSharedPreferences(context)
    private var encryption: Encryption


    // Key, Salt and Byte Array for Encryption
    private val KEY: String = key
    private val SALT: String = salt
    private val BYTE_ARRAY: Int = byteArray

    // Initialize Encryption
    init {
        encryption = Encryption(KEY, SALT, ByteArray(BYTE_ARRAY))
    }


    /**
     *  For Getting and storing value in Shared Preferences
     *
     */


    /**
     *  For Integer value
     *
     */

    fun getInt(key: String?) =
        encryption.decryptOrNull(sharedPreferences.getString(key, ""))?.toInt() ?: 0

    fun putInt(key: String?, value: Int) {
        sharedPreferences.edit().apply {
            putString(key, encryption.encryptOrNull(value.toString()))
            apply()
        }
    }


    /**
     *  For Float value
     *
     */

    fun putFloat(key: String?, value: Float) {
        sharedPreferences.edit().apply {
            putString(key, encryption.encryptOrNull(value.toString()))
            apply()
        }
    }

    fun getFloat(key: String?) =
        encryption.decryptOrNull(sharedPreferences.getString(key, ""))?.toFloat() ?: 0f


    /**
     *  For Long value
     *
     */

    fun putLong(key: String?, value: Long) {
        sharedPreferences.edit().apply {
            putString(key, encryption.encryptOrNull(value.toString()))
            apply()
        }
    }

    fun getLong(key: String?) =
        encryption.decryptOrNull(sharedPreferences.getString(key, ""))?.toLong() ?: 0L


    /**
     *  For String value
     *
     */
    fun putString(key: String?, value: String?) {
        sharedPreferences.edit().apply {
            putString(key, encryption.encryptOrNull(value))
            apply()
        }
    }

    fun getString(key: String?) =
        encryption.decryptOrNull(sharedPreferences.getString(key, "")) ?: ""


    fun getDecryptString(value: String?) =
        encryption.decryptOrNull(value) ?: ""


    /**
     *  For Boolean value
     *
     */

    fun putBoolean(key: String?, value: Boolean) {
        sharedPreferences.edit().apply {
            putString(key, encryption.encryptOrNull(value.toString()))
            apply()
        }
    }

    fun getBoolean(key: String?) =
        encryption.decryptOrNull(sharedPreferences.getString(key, "")).toBoolean()


    /**
     *  It will clear all the values which is stored in Shared Preferences
     *
     */

    fun clearAllPrefs() {
        val editor = sharedPreferences.edit()
        editor.clear()
        editor.apply()
    }


    /**
     * Encryption class for encrypting and decrypting values
     *
     */

    class Encryption(private val key: String, private val salt: String, iv: ByteArray) {

        private val base64Mode = Base64.DEFAULT
        private val iterationCount = 1
        private val algorithm: String = "AES/GCM/NoPadding"
        private val keyAlgorithm: String = "AES"
        private val charsetName: String = "UTF8"
        private val secretKeyType: String = "PBKDF2WithHmacSHA1"
        private val digestAlgorithm: String = "SHA1"
        private val secureRandomAlgorithm: String = "SHA1PRNG"
        private val mSecureRandom: SecureRandom = SecureRandom.getInstance(secureRandomAlgorithm)
        private val mIvParameterSpec: IvParameterSpec = IvParameterSpec(iv)
        private val keyLength = 128


        /**
         *  For encrypting the value using cipher
         *
         */
        @Throws(
            UnsupportedEncodingException::class,
            NoSuchAlgorithmException::class,
            NoSuchPaddingException::class,
            InvalidAlgorithmParameterException::class,
            InvalidKeyException::class,
            InvalidKeySpecException::class,
            BadPaddingException::class,
            IllegalBlockSizeException::class
        )
        private fun encrypt(data: String?): String? {
            if (data == null) return null
            val secretKey: SecretKey = getSecretKey(hashTheKey(key))
            val dataBytes = charset(charsetName).let { data.toByteArray(it) }
            val cipher: Cipher = Cipher.getInstance(algorithm)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                mIvParameterSpec,
                mSecureRandom
            )
            return Base64.encodeToString(cipher.doFinal(dataBytes), base64Mode)
        }


        fun encryptOrNull(data: String?): String? {
            return try {
                encrypt(data)
            } catch (e: Exception) {
                e.printStackTrace()
                ""
            }
        }

        fun encryptAsync(data: String?, callback: Callback?) {
            if (callback == null) return
            Thread {
                try {
                    val encrypt = encrypt(data)
                    if (encrypt == null) {
                        callback.onError(Exception("Encrypt return null, it normally occurs when you send a null data"))
                    }
                    callback.onSuccess(encrypt)
                } catch (e: Exception) {
                    callback.onError(e)
                }
            }.start()
        }


        /**
         *  For decrypting the value using cipher
         *
         */

        @Throws(
            UnsupportedEncodingException::class,
            NoSuchAlgorithmException::class,
            InvalidKeySpecException::class,
            NoSuchPaddingException::class,
            InvalidAlgorithmParameterException::class,
            InvalidKeyException::class,
            BadPaddingException::class,
            IllegalBlockSizeException::class
        )
        private fun decrypt(data: String?): String? {
            if (data == null) return null
            val dataBytes: ByteArray = Base64.decode(data, base64Mode)
            val secretKey: SecretKey = getSecretKey(hashTheKey(key))
            val cipher: Cipher = Cipher.getInstance(algorithm)
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                mIvParameterSpec,
                mSecureRandom
            )
            val dataBytesDecrypted: ByteArray = cipher.doFinal(dataBytes)
            return String(dataBytesDecrypted)

        }

        fun decryptOrNull(data: String?): String? {
            return try {
                decrypt(data)
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }

        fun decryptAsync(data: String?, callback: Callback?) {
            if (callback == null) return
            Thread {
                try {
                    val decrypt = decrypt(data)
                    if (decrypt == null) {
                        callback.onError(Exception("Decrypt return null, it normally occurs when you send a null data"))
                    }
                    callback.onSuccess(decrypt)
                } catch (e: Exception) {
                    callback.onError(e)
                }
            }.start()
        }


        @Throws(
            NoSuchAlgorithmException::class,
            UnsupportedEncodingException::class,
            InvalidKeySpecException::class
        )
        private fun getSecretKey(key: CharArray): SecretKey {
            val factory: SecretKeyFactory = SecretKeyFactory.getInstance(secretKeyType)
            val spec: KeySpec = PBEKeySpec(
                key,
                charset(charsetName).let { salt.toByteArray(it) },
                iterationCount,
                keyLength
            )
            val tmp: SecretKey = factory.generateSecret(spec)
            return SecretKeySpec(tmp.encoded, keyAlgorithm)
        }


        @Throws(UnsupportedEncodingException::class, NoSuchAlgorithmException::class)
        private fun hashTheKey(key: String?): CharArray {
            val messageDigest: MessageDigest = MessageDigest.getInstance(digestAlgorithm)
            messageDigest.update(key!!.toByteArray(charset(charsetName)))
            return Base64.encodeToString(messageDigest.digest(), Base64.NO_PADDING).toCharArray()
        }


        interface Callback {
            fun onSuccess(result: String?)
            fun onError(exception: Exception?)
        }

    }


}



