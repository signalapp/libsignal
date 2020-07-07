use crate::proto::storage::SessionStructure;

#[derive(Clone, Default)]
pub struct State {
    session_structure: SessionStructure,
}

impl State {
    const MAX_MESSAGE_KEYS: usize = 2000;

    pub fn new(session_structure: SessionStructure) -> Self {
        Self { session_structure }
    }
}
