use libsignal_bridge_macros::bridge_fn;
use libsignal_bridge_types::crypto::RandomNumberGenerator;
use libsignal_bridge_types::support::*;
use libsignal_bridge_types::*;

#[bridge_fn]
fn TESTING_EnableDeterministicRngForTesting() {
    RandomNumberGenerator::enable_deterministic_rng();
}
