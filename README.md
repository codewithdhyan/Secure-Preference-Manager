# Secure-Preference-Manager

Secure Preference Manager is a wrapper class used for storing the values of keys in encrypted form before storing them using cryptographic algorithms in the default Android Shared Preference Manager.

## Usage

To use the Secure Preference Manager, initialize it with the context, encryption key, initialization vector (IV), and key size. Then, use the `putString` method to store a value securely and the `getString` method to retrieve the value.

```kotlin
// Initialize the Secure Preference Manager
val securePreferenceManager = SecurePreferenceManager(this, "encryptionKey", "salt", 16)

// Store a value securely
securePreferenceManager.putString("key", "value")

// Retrieve the stored value
val value = securePreferenceManager.getString("key")
