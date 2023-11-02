use curve25519_dalek::scalar::Scalar;

const SHARE_SET: u8 = 1u8;
const MASK_SET: u8 = 2u8;
const MASKED_SHARE_SET: u8 = 4u8;

pub(crate) struct ServerSession {
    pub id: [u8; 16],
    share: [u8; 33],
    mask: [u8; 33],
    masked_share: [u8; 33],
    /// Bit flags of SHARE_SET, MASK_SET, and MASKED_SHARE_SET
    share_state: u8,
    pub blind: Scalar,
    oprf_input_bytes: Vec<u8>,
    oprf_input_ready: bool,
}

fn arr_xor<const N: usize>(lhs: &[u8; N], rhs: &[u8; N], dest: &mut [u8; N]) {
    for i in 0..33 {
        dest[i] = lhs[i] ^ rhs[i];
    }
}

impl ServerSession {
    pub(crate) fn new(id: [u8; 16], context: &'static str) -> Self {
        let mut oprf_input_bytes = Vec::<u8>::new();
        oprf_input_bytes.extend_from_slice(context.as_bytes());
        oprf_input_bytes.extend_from_slice(&id);

        Self {
            id,
            share: [0u8; 33],
            mask: [0u8; 33],
            masked_share: [0u8; 33],
            share_state: 0,
            blind: Scalar::ZERO,
            oprf_input_bytes,
            oprf_input_ready: false,
        }
    }

    pub(crate) fn get_share(&self) -> &[u8; 33] {
        if self.share_state & SHARE_SET != 0u8 {
            &self.share
        } else {
            unreachable!("accessing invalid share")
        }
    }

    #[cfg(test)]
    pub(crate) fn get_mask(&self) -> &[u8; 33] {
        if self.share_state & MASK_SET != 0u8 {
            &self.mask
        } else {
            unreachable!("accessing invalid mask")
        }
    }

    pub(crate) fn get_masked_share(&self) -> &[u8; 33] {
        if self.share_state & MASKED_SHARE_SET != 0u8 {
            &self.masked_share
        } else {
            unreachable!("accessing invalid masked share")
        }
    }

    pub(crate) fn set_share(&mut self, bytes: &[u8; 33]) {
        if (self.share_state & SHARE_SET) == SHARE_SET {
            debug_assert_eq!(bytes, &self.share);
        }

        self.share.copy_from_slice(bytes);
        self.share_state |= SHARE_SET;
        if self.share_state & MASK_SET != 0u8 {
            arr_xor(&self.share, &self.mask, &mut self.masked_share);
            self.share_state |= MASKED_SHARE_SET;
        } else if self.share_state & MASKED_SHARE_SET != 0u8 {
            arr_xor(&self.share, &self.masked_share, &mut self.mask);
            self.share_state |= MASK_SET;
        }
    }

    pub(crate) fn set_mask(&mut self, bytes: &[u8; 33]) {
        self.mask.copy_from_slice(bytes);
        self.share_state |= MASK_SET;
        if self.share_state & SHARE_SET != 0u8 {
            arr_xor(&self.share, &self.mask, &mut self.masked_share);
            self.share_state |= MASKED_SHARE_SET;
        } else if self.share_state & MASKED_SHARE_SET != 0u8 {
            arr_xor(&self.mask, &self.masked_share, &mut self.share);
            self.share_state |= SHARE_SET;
        }
    }

    pub(crate) fn set_masked_share(&mut self, bytes: &[u8; 33]) {
        self.masked_share.copy_from_slice(bytes);
        self.share_state |= MASKED_SHARE_SET;
        if self.share_state & MASK_SET != 0u8 {
            arr_xor(&self.masked_share, &self.mask, &mut self.share);
            self.share_state |= SHARE_SET;
        } else if self.share_state & SHARE_SET != 0u8 {
            arr_xor(&self.share, &self.masked_share, &mut self.mask);
            self.share_state |= MASK_SET;
        }
    }

    pub(crate) fn set_oprf_input(&mut self, input: &[u8]) {
        if self.oprf_input_ready {
            panic!("setting oprf input more than once.")
        }
        self.oprf_input_ready = true;
        self.oprf_input_bytes.extend_from_slice(input);
    }

    pub(crate) fn qualified_oprf_input(&self) -> &[u8] {
        if !self.oprf_input_ready {
            panic!("computing qualified oprf input before value was set.")
        }
        self.oprf_input_bytes.as_slice()
    }
}

impl PartialEq for ServerSession {
    fn eq(&self, other: &Self) -> bool {
        self.id[..] == other.id[..]
    }
}

impl Eq for ServerSession {}

impl PartialOrd for ServerSession {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ServerSession {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_setters() {
        let share = [1u8; 33];
        let mask = [3u8; 33];
        let masked_share = [2u8; 33];

        // set share then mask
        {
            let mut session_share_mask = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_share_mask.share_state, 0u8);

            session_share_mask.set_share(&share);
            assert_eq!(session_share_mask.share_state, SHARE_SET);
            session_share_mask.set_mask(&mask);
            assert_eq!(
                session_share_mask.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );
            assert_eq!(&masked_share, session_share_mask.get_masked_share());
        }

        // set mask then share
        {
            let mut session_mask_share = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_mask_share.share_state, 0u8);

            session_mask_share.set_mask(&mask);
            assert_eq!(session_mask_share.share_state, MASK_SET);
            session_mask_share.set_share(&share);
            assert_eq!(
                session_mask_share.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );

            assert_eq!(&masked_share, session_mask_share.get_masked_share());
        }
        // set masked_share then mask
        {
            let mut session_masked_share_mask = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_masked_share_mask.share_state, 0u8);

            session_masked_share_mask.set_masked_share(&masked_share);
            assert_eq!(session_masked_share_mask.share_state, MASKED_SHARE_SET);
            session_masked_share_mask.set_mask(&mask);
            assert_eq!(
                session_masked_share_mask.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );

            assert_eq!(&share, session_masked_share_mask.get_share());
        }
        // set mask then masked_share
        {
            let mut session_mask_masked_share = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_mask_masked_share.share_state, 0u8);

            session_mask_masked_share.set_mask(&mask);
            assert_eq!(session_mask_masked_share.share_state, MASK_SET);
            session_mask_masked_share.set_masked_share(&masked_share);
            assert_eq!(
                session_mask_masked_share.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );

            assert_eq!(&share, session_mask_masked_share.get_share());
        }
        // set share then masked_share (not so useful in practice, but we'll cover it)
        {
            let mut session_share_masked_share = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_share_masked_share.share_state, 0u8);

            session_share_masked_share.set_share(&share);
            assert_eq!(session_share_masked_share.share_state, SHARE_SET);
            session_share_masked_share.set_masked_share(&masked_share);
            assert_eq!(
                session_share_masked_share.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );

            assert_eq!(&mask, session_share_masked_share.get_mask());
        }
        // set masked_share then share (not so useful in practice, but we'll cover it)
        {
            let mut session_masked_share_share = ServerSession::new([5u8; 16], "test context");
            assert_eq!(session_masked_share_share.share_state, 0u8);

            session_masked_share_share.set_masked_share(&masked_share);
            assert_eq!(session_masked_share_share.share_state, MASKED_SHARE_SET);
            session_masked_share_share.set_share(&share);
            assert_eq!(
                session_masked_share_share.share_state,
                SHARE_SET | MASK_SET | MASKED_SHARE_SET
            );

            assert_eq!(&mask, session_masked_share_share.get_mask());
        }
    }
}
