# SWOOSH Alice/Bob Role Determination Solutions

## Problem Analysis

The SWOOSH (Post-Quantum Signal With Out Of band Synchronization Helper) protocol requires knowing who is Alice and who is Bob because:

1. **Matrix Usage**: Alice uses the original matrix `A`, while Bob uses the transpose `A^T`
2. **Key Derivation**: The `pswoosh_skey_deriv` function uses different computation orders:
   - `f = false`: Computes `pk * s` (standard multiplication)
   - `f = true`: Computes `s^T * pk` (transpose multiplication)
3. **Public Key Ordering**: The order of public keys in the input changes based on the role

## Issues in Original Implementation

1. **Non-deterministic Role Assignment**: Using lexicographic comparison of ephemeral keys leads to inconsistent results
2. **Hardcoded Alice Role**: Session initialization hardcoded Alice as `true`
3. **Lack of Context**: No consideration of session initiation context

## Implemented Solutions

### Solution 1: Deterministic Role Assignment Based on Identity Keys

**File**: `/rust/protocol/src/ratchet/keys.rs`

Added a new function `determine_swoosh_role()` that uses identity keys for consistent role determination:

```rust
/// Determine Alice/Bob role based on identity keys for SWOOSH
/// This provides a deterministic way to assign roles that both parties will agree on
pub(crate) fn determine_swoosh_role(
    our_identity: &IdentityKey,
    their_identity: &IdentityKey,
) -> bool {
    // Use lexicographic comparison of identity key bytes
    // The party with the lexicographically smaller identity key is Alice
    our_identity.serialize() < their_identity.serialize()
}
```

**Benefits**:
- Both parties will always compute the same result
- Uses existing, stable identity keys
- Deterministic and reproducible
- No dependency on ephemeral session state

### Solution 2: Updated Session Cipher Role Determination

**File**: `/rust/protocol/src/session_cipher.rs`

Updated `get_or_create_chain_key_swoosh()` to use the deterministic role assignment:

```rust
// Determine role based on identity keys for deterministic role assignment
let our_identity = state.local_identity_key().map_err(|e| {
    SignalProtocolError::InvalidState("get_or_create_chain_key_swoosh", format!("Cannot get local identity: {}", e).into())
})?;
let their_identity = state.remote_identity_key().map_err(|e| {
    SignalProtocolError::InvalidState("get_or_create_chain_key_swoosh", format!("Cannot get remote identity: {}", e).into())
})?.ok_or_else(|| {
    SignalProtocolError::InvalidState("get_or_create_chain_key_swoosh", "No remote identity available".into())
})?;
let is_alice = RootKey::determine_swoosh_role(&our_identity, &their_identity);
```

### Solution 3: Updated Ratchet Initialization

**File**: `/rust/protocol/src/ratchet.rs`

Updated Alice session initialization to use deterministic role assignment:

```rust
let swoosh_sending_key = SwooshKeyPair::generate(&A, true);
// Use deterministic role assignment: Alice has lexicographically smaller identity key
let is_alice = RootKey::determine_swoosh_role(
    parameters.our_identity_key_pair().identity_key(),
    parameters.their_identity_key()
);
let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain_swoosh(
    parameters.their_swoosh_ratchet_key().unwrap(),
    &swoosh_sending_key.public_key(),
    &swoosh_sending_key.private_key(),
    is_alice
)?;
```

## Alternative Solutions (Not Implemented)

### Alternative 1: Session Initiator-Based Role Assignment
- Use protocol-level session initiation context
- Alice = session initiator, Bob = session responder
- Requires tracking session initiation state

### Alternative 2: Explicit Role Negotiation
- Add explicit Alice/Bob role negotiation to protocol handshake
- Store role information in session state
- More complex but most explicit

### Alternative 3: Time-Based Role Assignment
- Use timestamp comparison for role determination
- Less reliable due to clock synchronization issues

## Key Design Decisions

1. **Identity Key Comparison**: Using identity keys ensures both parties compute the same result since these keys are exchanged during session establishment.

2. **Lexicographic Ordering**: Simple, deterministic, and language-agnostic comparison method.

3. **Fallback Safety**: The implementation includes proper error handling for cases where identity keys are not available.

4. **Backwards Compatibility**: Changes maintain compatibility with existing session structures.

## Testing Recommendations

1. **Cross-Platform Testing**: Verify that both parties compute the same role across different platforms
2. **Identity Key Edge Cases**: Test with identical identity keys (though this should never happen in practice)
3. **Session Recovery**: Test role determination during session state recovery
4. **Performance**: Measure any performance impact of the additional role determination logic

## Security Considerations

1. **No Information Leakage**: Role determination doesn't reveal any private information
2. **Consistency**: Both parties will always agree on roles, preventing protocol failures
3. **Non-Malleability**: An attacker cannot manipulate role assignment without controlling identity keys

## Implementation Status

✅ **Implemented**: Deterministic role assignment based on identity keys
✅ **Implemented**: Updated session cipher role determination
✅ **Implemented**: Updated ratchet initialization
✅ **Verified**: Code compiles without errors
⏳ **Pending**: Testing with actual SWOOSH protocol execution
⏳ **Pending**: Cross-platform compatibility verification
