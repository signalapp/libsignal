//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

import org.signal.libsignal.internal.Native;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Username {
    private String value;
    private byte[] hash;

    public Username(String username) throws BaseUsernameException {
        this.value = username;
        this.hash = hash(username);
    }

    public String getUsername() {
        return this.value;
    }

    public byte[] getHash() {
        return this.hash;
    }

    public static List<Username> candidatesFrom(String nickname, int minNicknameLength, int maxNicknameLength) throws BaseUsernameException {
        String names = Native.Username_CandidatesFrom(nickname, minNicknameLength, maxNicknameLength);
        ArrayList<Username> result = new ArrayList<>();
        for (String name : names.split(",")) {
            result.add(new Username(name));
        }
        return result;
    }

    public byte[] generateProof() throws BaseUsernameException {
        byte[] randomness = new byte[32];
        SecureRandom r = new SecureRandom();
        r.nextBytes(randomness);
        return generateProofWithRandomness(randomness);
    }

    public byte[] generateProofWithRandomness(byte[] randomness) throws BaseUsernameException {
        return Native.Username_Proof(this.value, randomness);
    }

    @Deprecated
    public static List<String> generateCandidates(String nickname, int minNicknameLength, int maxNicknameLength) throws BaseUsernameException {
        String names = Native.Username_CandidatesFrom(nickname, minNicknameLength, maxNicknameLength);
        return Arrays.asList(names.split(","));
    }

    @Deprecated
    public static byte[] hash(String username) throws BaseUsernameException {
        return Native.Username_Hash(username);
    }

    @Deprecated
    public static byte[] generateProof(String username, byte[] randomness) throws BaseUsernameException {
        return Native.Username_Proof(username, randomness);
    }

    public static void verifyProof(byte[] proof, byte[] hash) throws BaseUsernameException {
        Native.Username_Verify(proof, hash);
    }

    @Override
    public String toString() {
        return this.value;
    }
}
