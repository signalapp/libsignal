v0.105.1

- Simplified zkcredential presentations involving multiple attribute encryption keys. The previous form only fully established proof-of-knowledge when the public keys were all known in advance by the verifying server, which the library cannot guarantee. Signal does not currently use zkcredential for any credentials with multiple attribute encryption keys (the only one is ProfileKeyCredential, which is still using a manually-written implementation), so there is no compatibility break for Signal's services, but external uses of zkcredential may need to adjust.

- New typed APIs:
    - Donations.createDonationPermits
    - Donations.redeemDonationReceipt
    - AuthAccountsService.getAccountEntitlements (just getEntitlements for Kotlin)
