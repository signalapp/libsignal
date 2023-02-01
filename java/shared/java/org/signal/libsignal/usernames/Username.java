//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

import org.signal.libsignal.internal.Native;

import java.util.Arrays;
import java.util.List;

public final class Username {
    public static List<String> generateCandidates(String nickname, int minNicknameLength, int maxNicknameLength) throws BaseUsernameException {
        String names = Native.Username_CandidatesFrom(nickname, minNicknameLength, maxNicknameLength);
        return Arrays.asList(names.split(","));
    }

    public static byte[] hash(String username) throws BaseUsernameException {
        return Native.Username_Hash(username);
    }

    public static byte[] generateProof(String username, byte[] randomness) throws BaseUsernameException {
        return Native.Username_Proof(username, randomness);
    }

    public static void verifyProof(byte[] proof, byte[] hash) throws BaseUsernameException {
        Native.Username_Verify(proof, hash);
    }
}
