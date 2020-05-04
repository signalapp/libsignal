mod keys;
mod params;

pub use self::keys::{ChainKey, MessageKeys, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use super::{curve, state::SessionState, HKDF};

pub fn initialize_alice_session(
    session_state: &mut SessionState,
    parameters: &AliceSignalProtocolParameters,
) {
}
