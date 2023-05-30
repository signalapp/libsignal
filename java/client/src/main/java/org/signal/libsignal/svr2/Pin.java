//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.svr2;

import org.signal.libsignal.internal.Native;

/**
 * Supports operations on pins for Secure Value Recovery
 * <p>
 * This class provides hashing pins for local verification and for use with the remote SVR service. In either case, all
 * pins are UTF-8 encoded bytes that must be normalized *before* being provided to this class. Normalizing a string pin
 * requires the following steps:
 *
 * <li> The string should be trimmed for leading and trailing whitespace. </li>
 * <li> If the whole string consists of digits, then non-arabic digits must be replaced with their
 * arabic 0-9 equivalents. </li>
 * <li> The string must then be <a href="https://unicode.org/reports/tr15/#Norm_Forms">NKFD normalized</a> </li>
 */
public class Pin {

    private Pin() {
    }

    /**
     * Create an encoded password hash string.
     *
     * This creates a hashed pin that should be used for local pin verification only.
     *
     * @param pin A normalized, UTF-8 encoded byte representation of the pin
     * @return A hashed pin string that can be verified later
     */
    public static String localHash(final byte[] pin) {
        return Native.Pin_LocalHash(pin);
    }

    /**
     * Verify an encoded password hash against a pin
     *
     * @param encodedHash An encoded string of the hash, as returned by {@link Pin#localHash}
     * @param pin A normalized, UTF-8 encoded byte representation of the pin to verify
     * @return true if the pin matches the hash, false otherwise
     */
    public static boolean verifyLocalHash(final String encodedHash, final byte[] pin) {
        return Native.Pin_VerifyLocalHash(encodedHash, pin);
    }
}
