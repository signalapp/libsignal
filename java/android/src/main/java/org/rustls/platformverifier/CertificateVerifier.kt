// Forked from https://github.com/rustls/rustls-platform-verifier/blob/v/0.5.1/android/rustls-platform-verifier/src/main/java/org/rustls/platformverifier/CertificateVerifier.kt.
// under the MIT License:
//
//     Copyright (c) 2022 1Password
//
//     Permission is hereby granted, free of charge, to any person obtaining a copy
//     of this software and associated documentation files (the "Software"), to deal
//     in the Software without restriction, including without limitation the rights
//     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//     copies of the Software, and to permit persons to whom the Software is
//     furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in all
//     copies or substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//     SOFTWARE.
//
// Additional modifications Copyright 2025 Signal Messenger, LLC.

// We use the same package and class name to avoid having to change the Rust side of the bridge.
package org.rustls.platformverifier

import android.annotation.SuppressLint
import android.content.Context
import android.net.http.X509TrustManagerExtensions
import android.os.Build
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXRevocationChecker
import java.security.cert.X509Certificate
import java.util.Date
import java.util.EnumSet
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

// If this is updated, update the Rust definition too.
// Marked private as this is not meant to be used in Android code.
private enum class StatusCode(val value: Int) {
    Ok(0),
    Unavailable(1),
    Expired(2),
    UnknownCert(3),
    Revoked(4),
    InvalidEncoding(5),
    InvalidExtension(6),
}

// Marked private as this is not meant to be used in Android code.
private class VerificationResult(
    status: StatusCode,
    @Suppress("unused") val message: String? = null
) {
    @Suppress("unused")
    private val code: Int = status.value
}

// ADDED BY SIGNAL: Takes the place of an Android library BuildConfig.
private object BuildConfig {
    const val TEST: Boolean = false
}

// NOTE: All TrustManager and certificate validation methods are not thread safe. These
// are all guarded by Kotlin's `Synchronized` accessors to prevent undefined behavior.

// Only JNI and test code calls this, so unused code warnings are suppressed.
// Internal for test code - no other Kotlin code should use this object directly.
// MODIFIED FOR SIGNAL: exposed as public so we can set `shouldCheckRevocation`
@Suppress("unused")
// We want to show a difference between Kotlin-side logs and those in Rust code
@SuppressLint("LongLogTag")
public object CertificateVerifier {
    private const val TAG = "rustls-platform-verifier-android"

    // ADDED BY SIGNAL
    @JvmStatic
    public var shouldCheckRevocation: Boolean = false

    private fun createTrustManager(keystore: KeyStore?): X509TrustManagerExtensions? {
        // This can never throw since the default algorithm is used.
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

        factory.init(keystore)

        val availableTrustManagers = try {
            factory.trustManagers
        } catch (e: RuntimeException) {
            Log.w(TAG, "exception thrown creating a TrustManager: $e")
            return null
        }

        for (manager in availableTrustManagers) {
            if (manager is X509TrustManager) {
                // Kotlin ensures this can't throw at runtime since it knows that
                // it must be the correct type by now.
                return X509TrustManagerExtensions(manager)
            }
        }

        Log.e(TAG, "failed to find a usable trust manager")
        return null
    }

    private fun makeLazyTrustManager(keystore: KeyStore?): Lazy<X509TrustManagerExtensions?> {
        // Ensure the keystore is loaded. Since all of the trust managers are initialized in a
        // `Lazy`, this will only run once.
        keystore?.load(null)

        return lazy { createTrustManager(keystore) }
    }

    // -- Test only --
    // Ideally, all of this will be optimized out at compile time due to not being accessed
    // in release builds.

    @get:Synchronized
    private val mockKeystore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())

    @get:Synchronized
    private var mockTrustManager: Lazy<X509TrustManagerExtensions?> =
        makeLazyTrustManager(mockKeystore)

    @JvmStatic
    private fun addMockRoot(root: ByteArray) {
        if (!BuildConfig.TEST) {
            throw Exception("attempted to add a mock root outside a test!")
        }

        val alias = "root_${mockKeystore.size()}"
        // Throwing here is fine since test roots should always be well-formed
        val cert = certFactory.generateCertificate(ByteArrayInputStream(root))
        mockKeystore.setCertificateEntry(alias, cert)

        reloadMockData()
    }

    @JvmStatic
    private fun clearMockRoots() {
        // Reload to get a completely fresh internal state
        mockKeystore.load(null)
        reloadMockData()
    }

    @JvmStatic
    private fun reloadMockData() {
        if (mockTrustManager.isInitialized()) {
            mockTrustManager = makeLazyTrustManager(mockKeystore)
        }
    }

    // Get a list of the system's root CAs.
    // Function is public for testing only.
    @JvmStatic
    public fun getSystemRootCAs(): List<X509Certificate> {
        val rootCAs = mutableListOf<X509Certificate>()

        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(systemKeystore)

        val availableTrustManagers = try {
            factory.trustManagers
        } catch (e: RuntimeException) {
            Log.w(TAG, "exception thrown creating a TrustManager: $e")
            return rootCAs
        }

        availableTrustManagers.forEach { trustManager ->
            if (trustManager is X509TrustManager) {
                rootCAs.addAll(trustManager.acceptedIssuers)
            }
        }

        return rootCAs
    }

    // -- End testing requirements --

    private val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

    private var systemTrustAnchorCache = hashSetOf<Pair<X500Principal, PublicKey>>()

    @get:Synchronized
    private var systemCertificateDirectory: File? = System.getenv("ANDROID_ROOT")?.let { rootPath ->
        File("$rootPath/etc/security/cacerts")
    }

    @get:Synchronized
    private val systemKeystore: KeyStore? = try {
        KeyStore.getInstance("AndroidCAStore")
    } catch (_: KeyStoreException) {
        null
    }

    @get:Synchronized
    private val systemTrustManager: Lazy<X509TrustManagerExtensions?> =
        makeLazyTrustManager(systemKeystore)

    @JvmStatic
    private fun verifyCertificateChain(
        @Suppress("UNUSED_PARAMETER") context: Context,
        serverName: String,
        authMethod: String,
        allowedEkus: Array<String>,
        ocspResponse: ByteArray?,
        time: Long,
        certChain: Array<ByteArray>
    ): VerificationResult {
        // Convert the array of (supposedly) DER bytes into certificates.
        val certificateChain = mutableListOf<X509Certificate>()
        certChain.forEach { certBytes ->
            val certificate = try {
                certFactory.generateCertificate(ByteArrayInputStream(certBytes))
            } catch (e: CertificateException) {
                return VerificationResult(StatusCode.InvalidEncoding)
            }
            certificateChain.add(certificate as X509Certificate)
        }

        // Will never throw `ArrayIndexOutOfBoundsException` because `rustls`'s `ServerCertVerifier` trait
        // has a mandatory `end_entity` parameter in `verify_server_cert`.
        val endEntity = certificateChain[0]

        // Check that the certificate is valid at the point of time provided by `rustls`.
        try {
            endEntity.checkValidity(Date(time))
        } catch (e: CertificateExpiredException) {
            return VerificationResult(StatusCode.Expired)
        } catch (e: CertificateNotYetValidException) {
            return VerificationResult(StatusCode.Expired)
        }

        // Check that this certificate can be used in a TLS server.
        if (!verifyCertUsage(endEntity, allowedEkus)) {
            return VerificationResult(StatusCode.InvalidExtension)
        }

        // Select the trust manager to use.
        //
        // We select them as follows:
        // - If built for release, only use the system trust manager. This should let all test-related
        // code be optimized out.
        // - If built for tests:
        //      - If the mock CA store has any values, use the mock trust manager.
        //      - Otherwise, use the system trust manager.
        val (trustManager, keystore) = if (!BuildConfig.TEST) {
            val trustManager =
                systemTrustManager.value ?: return VerificationResult(StatusCode.Unavailable)
            Pair(trustManager, systemKeystore)
        } else {
            if (mockKeystore.size() != 0) {
                val trustManager = mockTrustManager.value!!
                Pair(trustManager, mockKeystore)
            } else {
                val trustManager =
                    systemTrustManager.value ?: return VerificationResult(StatusCode.Unavailable)
                Pair(trustManager, systemKeystore)
            }
        }

        // Verify that the certificate chain is valid and correct, and nothing more.
        //
        // NOTE: This does not validate `serverName` is valid for the end-entity certificate.
        // That is handled in Rust as Android/Java do not currently provide a RFC 6125 compliant
        // hostname verifier. Additionally, even the RFC 2818 verifier is not available until API 24.
        //
        // `serverName` is only used for pinning/CT requirements.
        //
        // Returns the "the properly ordered chain used for verification as a list of X509Certificates.",
        // meaning a list from end-entity certificate to trust-anchor.
        val validChain = try {
            trustManager.checkServerTrusted(certificateChain.toTypedArray(), authMethod, serverName)
        } catch (e: CertificateException) {
            // In test configurations we may see `checkServerTrusted` fail once vendored test
            // certificates pass their expiry date. We try to avoid that by using a fixed
            // verification time when calling `endEntity.checkValidity` above, however we can't
            // fix the time for the `checkServerTrusted` call.
            //
            // To make diagnosing CI test failures easier we try to find the root cause of
            // checkServerTrusted failing, returning a different `StatusCode` as appropriate.
            if (BuildConfig.TEST) {
                var rootCause: Throwable? = e
                while (rootCause?.cause != null && rootCause.cause != rootCause) {
                    rootCause = rootCause.cause
                }
                return when (rootCause) {
                    is CertificateExpiredException, is CertificateNotYetValidException -> VerificationResult(
                        StatusCode.Expired,
                        rootCause.toString()
                    )

                    else -> VerificationResult(StatusCode.UnknownCert, rootCause.toString())
                }
            }
            // In non-test configurations we should have caught expiry errors earlier and
            // can simply return an unknown cert error without digging through the exception
            // cause chain.
            return VerificationResult(StatusCode.UnknownCert, e.toString())
        }

        // TEST ONLY: Mock test suite cannot attempt to check revocation status if no OSCP data has been stapled,
        // because Android requires certificates to an specify OCSP responder for network fetch in this case.
        // If in testing w/o OCSP stapled, short-circuit here - only prior checks apply.
        if (BuildConfig.TEST && (mockKeystore.size() != 0) && (ocspResponse == null)) {
            return VerificationResult(StatusCode.Ok)
        }

        // Try to check the revocation status of the cert, if it is supported.
        //
        // This is supported at >= API 24, but we're supporting 22 (Android 5) for the best
        // compatibility.
        //
        // MODIFIED BY SIGNAL: only if shouldCheckRevocation is set.
        if (shouldCheckRevocation && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // Note:
            //
            // 1. Android does not provide any way only to attempt to validate revocation from cached
            // data like the other platforms do. This means it will always use the network for
            // certificates which had no stapled response.
            //
            // 2: Likely because of 1, Android requires all issued certificates to have some form of
            // revocation included in their authority information. This doesn't work universally as
            // issuing certificates in use may omit authority access information (for example the
            // Let's Encrypt R3 Intermediate Certificate).
            //
            // Given these constraints, the best option is to only check revocation information
            // at the end-entity depth. We will prefer OCSP (to use stapled information if possible).
            // If there is no stapled OCSP response, Android may use the network to attempt to fetch
            // one. If OCSP checking fails, it may fall back to fetching CRLs. We allow "soft"
            // failures, for example transient network errors.
            //
            // In the case of a non-public root, such as an internal CA or self-signed certificate,
            // we opt to skip revocation checks entirely. The only exception is if the server
            // provided stapled OCSP data, which is an explicit signal and won't introduce non-ideal
            // platform behavior when attempting validation.
            //
            // This is because these are cases where a user or administrator has explicitly opted to
            // trust a certificate they (at least believe) have control over. These certificates rarely
            // contain revocation information as well, so these cases don't lose much.
            // See https://github.com/rustls/rustls-platform-verifier/issues/69 as well.
            if (ocspResponse == null && !isKnownRoot(validChain.last())) {
                // Chain validation must have succeeded by this point.
                return VerificationResult(StatusCode.Ok)
            }

            val parameters = PKIXBuilderParameters(keystore, null)

            val validator = CertPathValidator.getInstance("PKIX")
            val revocationChecker = validator.revocationChecker as PKIXRevocationChecker

            revocationChecker.options = EnumSet.of(
                PKIXRevocationChecker.Option.SOFT_FAIL,
                PKIXRevocationChecker.Option.ONLY_END_ENTITY
            )

            // Use the OCSP data `rustls` provided, if present.
            // Its expected that the server only sends revocation data for its own leaf certificate.
            //
            // If this field is set, then Android will use it and skip any networking to
            // attempt a fetch for that certificate. Otherwise, it will attempt to fetch it from the network.
            // Ref: https://cs.android.com/android/platform/superproject/+/master:libcore/ojluni/src/main/java/sun/security/provider/certpath/RevocationChecker.java;l=694
            ocspResponse?.let { providedResponse ->
                revocationChecker.ocspResponses = mapOf(endEntity to providedResponse)
            }

            // Use the custom revocation definition.
            // "Note that when a `PKIXRevocationChecker` is added to `PKIXParameters`, it clones the `PKIXRevocationChecker`;
            // thus any subsequent modifications to the `PKIXRevocationChecker` have no effect."
            //  - https://developer.android.com/reference/java/security/cert/PKIXRevocationChecker
            parameters.certPathCheckers = listOf(revocationChecker)
            // "When supplying a revocation checker in this manner, it will be used to check revocation
            // irrespective of the setting of the `RevocationEnabled` flag."
            //  - https://developer.android.com/reference/java/security/cert/PKIXRevocationChecker
            parameters.isRevocationEnabled = false

            // Validate the revocation status of the end entity certificate.
            try {
                validator.validate(certFactory.generateCertPath(validChain), parameters)
            } catch (e: CertPathValidatorException) {
                return VerificationResult(StatusCode.Revoked, e.toString())
            }

        // MODIFIED BY SIGNAL: The warning log used to be unconditional.
        } else if (shouldCheckRevocation) {
            // This is allowed to be skipped since revocation checking is best-effort.
            Log.w(TAG, "did not attempt to validate OCSP due to Android version")
        } else {
            Log.v(TAG, "note: revocation checking disabled")
        }

        return VerificationResult(StatusCode.Ok)
    }

    private fun verifyCertUsage(certificate: X509Certificate, allowedEkus: Array<String>): Boolean {
        val ekus = try {
            certificate.extendedKeyUsage
        }
        // This should be unreachable, but could happen.
        catch (_: CertificateParsingException) {
            return false
        } catch (_: NullPointerException) {
            // According to Chromium's implementation, this can crash when the EKU data is malformed.
            Log.w(TAG, "exception handling certificate EKU")
            return false
        } ?: return true // If the list is empty, we have nothing to do.

        return ekus.any { allowedEkus.contains(it) }
    }

    // Android hashes a principal using the first four bytes of its MD5 digest, encoded in
    // lowercase hex and reversed.
    //
    // Ref: https://source.chromium.org/chromium/chromium/src/+/main:net/android/java/src/org/chromium/net/X509Util.java;l=339
    private fun hashPrincipal(principal: X500Principal): String {
        val hexDigits = "0123456789abcdef".toCharArray()
        val digest = MessageDigest.getInstance("MD5").digest(principal.encoded)
        val hexChars = CharArray(8)

        for (i in 0..3) {
            // Kotlin doesn't support bitwise operators for bytes, only Int and Long.
            val digestByte = digest[3 - i].toInt()
            hexChars[2 * i] = hexDigits[(digestByte shr 4) and 0xf]
            hexChars[2 * i + 1] = hexDigits[digestByte and 0xf]
        }

        return String(hexChars)
    }

    // Check if CA root is known or not.
    // Known means installed in root CA store, either a preset public CA or a custom one installed by an enterprise/user.
    //
    // Ref: https://source.chromium.org/chromium/chromium/src/+/main:net/android/java/src/org/chromium/net/X509Util.java;l=351
    public fun isKnownRoot(root: X509Certificate): Boolean {
        // System keystore and cert directory must be non-null to perform checking
        systemKeystore?.let { loadedSystemKeystore ->
            systemCertificateDirectory?.let { loadedSystemCertificateDirectory ->

                // Check the in-memory cache first
                val key = Pair(root.subjectX500Principal, root.publicKey)
                if (systemTrustAnchorCache.contains(key)) {
                    return true
                }

                // System trust anchors are stored under a hash of the principal.
                // In case of collisions, append number.
                val hash = hashPrincipal(root.subjectX500Principal)
                var i = 0
                while (true) {
                    val alias = "$hash.$i"

                    if (!File(loadedSystemCertificateDirectory, alias).exists()) {
                        break
                    }

                    val anchor = loadedSystemKeystore.getCertificate("system:$alias")

                    // It's possible for `anchor` to be `null` if the user deleted a trust anchor.
                    // Continue iterating as there may be further collisions after the deleted anchor.
                    if (anchor == null) {
                        continue
                        // This should never happen
                    } else if (anchor !is X509Certificate) {
                        // SAFETY: This logs a unique identifier (hash value) only in cases where a file within the
                        // system's root trust store is not a valid X509 certificate (extremely unlikely error).
                        // The hash doesn't tell us any sensitive information about the invalid cert or reveal any of
                        // its contents - it just lets us ID the bad file if a user is having TLS failure issues.
                        Log.e(TAG, "anchor is not a certificate, alias: $alias")
                        continue
                        // If subject and public key match, it's a system root.
                    } else {
                        if ((root.subjectX500Principal == anchor.subjectX500Principal) && (root.publicKey == anchor.publicKey)) {
                            systemTrustAnchorCache.add(key)
                            return true
                        }
                    }

                    i += 1
                }
            }
        }

        // Not found in cache or store: non-public
        return false
    }
}
