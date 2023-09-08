//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.usernames;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import org.signal.libsignal.internal.Native;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class Username {
    private final String username;
    private final byte[] hash;

    public static class UsernameLink {
        private final byte[] entropy;
        private final byte[] encryptedUsername;

        public UsernameLink(final byte[] entropy, final byte[] encryptedUsername) {
            this.entropy = Objects.requireNonNull(entropy, "entropy");
            this.encryptedUsername = Objects.requireNonNull(encryptedUsername, "encryptedUsername");
        }

        public byte[] getEntropy() {
            return entropy;
        }

        public byte[] getEncryptedUsername() {
            return encryptedUsername;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            final UsernameLink that = (UsernameLink) o;
            return Arrays.equals(entropy, that.entropy) &&
                Arrays.equals(encryptedUsername, that.encryptedUsername);
        }

        @Override
        public int hashCode() {
            int result = Arrays.hashCode(entropy);
            result = 31 * result + Arrays.hashCode(encryptedUsername);
            return result;
        }
    }

    public Username(String username) throws BaseUsernameException {
        this.username = Objects.requireNonNull(username, "username");
        this.hash = hash(username);
    }

    public String getUsername() {
        return this.username;
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

    public static Username fromLink(final UsernameLink usernameLink) throws BaseUsernameException {
        final String username = Native.UsernameLink_DecryptUsername(usernameLink.getEntropy(), usernameLink.getEncryptedUsername());
        return new Username(username);
    }

    public byte[] generateProof() throws BaseUsernameException {
        byte[] randomness = new byte[32];
        SecureRandom r = new SecureRandom();
        r.nextBytes(randomness);
        return generateProofWithRandomness(randomness);
    }

    public byte[] generateProofWithRandomness(byte[] randomness) throws BaseUsernameException {
        return Native.Username_Proof(this.username, randomness);
    }

    public UsernameLink generateLink() throws BaseUsernameException  {
        final byte[] bytes = Native.UsernameLink_Create(username);
        final byte[] entropy = Arrays.copyOfRange(bytes, 0, 32);
        final byte[] enctyptedUsername = Arrays.copyOfRange(bytes, 32, bytes.length);
        return new UsernameLink(entropy, enctyptedUsername);
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
        return this.username;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final Username username1 = (Username) o;
        return username.equals(username1.username);
    }

    @Override
    public int hashCode() {
        return username.hashCode();
    }
}
