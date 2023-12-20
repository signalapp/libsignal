//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use arrayvec::ArrayVec;
use futures::io::{AsyncRead, AsyncReadExt as _};

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub(crate) enum ParseError {
    /// io: {0}
    Io(#[from] std::io::Error),
    /// proto decode error: {0}
    Decode(#[from] prost::DecodeError),
}

const VARINT_MAX_LENGTH: usize = 10;

pub(crate) struct VarintDelimitedReader<R> {
    #[allow(unused)]
    reader: R,
    #[allow(unused)]
    buffer: ArrayVec<u8, VARINT_MAX_LENGTH>,
}

impl<R: AsyncRead + Unpin> VarintDelimitedReader<R> {
    #[allow(unused)]
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: ArrayVec::new(),
        }
    }

    pub(crate) async fn read_next(&mut self) -> Result<Option<Box<[u8]>>, ParseError> {
        let length = match self.read_next_varint().await? {
            None => return Ok(None),
            Some(length) => length,
        };

        let Self { reader, buffer } = self;

        // Read `length` bytes, first from the buffer, then from the reader.
        let mut buf = Vec::with_capacity(length);
        let buffered_byte_count = length.min(buffer.len());
        buf.extend_from_slice(&buffer[..buffered_byte_count]);
        buffer.drain(..buffered_byte_count);

        if buffered_byte_count < length {
            buf.resize(length, 0);

            reader.read_exact(&mut buf[buffered_byte_count..]).await?;
        }

        Ok(Some(buf.into_boxed_slice()))
    }

    async fn read_next_varint(&mut self) -> Result<Option<usize>, ParseError> {
        let Self { buffer, reader } = self;

        // First fill up the buffer with zeros so it can be treated as a slice.
        // Keep track of how many bytes in the buffer have actually been read
        // from the reader.
        let mut read_bytes = buffer.len();
        buffer.extend(
            [0; VARINT_MAX_LENGTH][..buffer.remaining_capacity()]
                .iter()
                .cloned(),
        );

        // Read into the invalid portion until it's full or the reader is empty.
        loop {
            let n = reader.read(&mut buffer[read_bytes..]).await?;
            if n == 0 {
                break;
            }
            read_bytes += n;
        }

        // Chop off any zeroed-but-not-read bytes.
        buffer.truncate(read_bytes);

        if read_bytes == 0 {
            return Ok(None);
        }

        // Create a view into the bytes of the buffer. The bytes consumed during
        // varint decoding are removed from the head of this slice.
        let mut view = &buffer[..read_bytes];

        let length =
            prost::decode_length_delimiter(&mut view).map_err(|_: prost::DecodeError| {
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
            })?;

        // Remove the consumed bytes from the buffer.
        let consumed_byte_count = read_bytes - view.len();
        buffer.drain(..consumed_byte_count);

        Ok(Some(length))
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use futures::pin_mut;

    use super::*;

    #[test]
    fn read_length_delimited_empty() {
        let bytes = [];
        let reader = VarintDelimitedReader::new(bytes.as_slice());
        pin_mut!(reader);

        assert_matches!(block_on(reader.read_next()), Ok(None));
    }

    #[test]
    fn read_length_delimited_truncated() {
        const MESSAGE_SIZE: usize = 10;
        const VARINT_LEN: usize = 1;

        let mut short_buf = [0; VARINT_LEN + MESSAGE_SIZE - 1];
        {
            let mut varint_window = &mut short_buf[..VARINT_LEN];
            prost::encode_length_delimiter(MESSAGE_SIZE, &mut varint_window)
                .expect("can hold varint");
            assert_eq!(varint_window, &[]);
        }

        let reader = VarintDelimitedReader::new(short_buf.as_slice());
        pin_mut!(reader);

        assert_matches!(
            block_on(reader.read_next()),
            Err(ParseError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof
        );
    }
    struct MessageAndLen<const L: usize, const M: usize> {
        varint: [u8; L],
        message: [u8; M],
    }

    impl<const L: usize, const M: usize> MessageAndLen<L, M> {
        const fn new(varint: [u8; L], message: [u8; M]) -> Self {
            Self { varint, message }
        }

        fn into_reader(self) -> impl AsyncRead {
            Cursor::new(self.varint).chain(Cursor::new(self.message))
        }
    }

    #[track_caller]
    fn assert_valid<const M: usize, const L: usize>(
        MessageAndLen { varint, message }: &MessageAndLen<M, L>,
    ) {
        let mut buf = [0u8; L];
        let mut buf_view = buf.as_mut();
        prost::encode_length_delimiter(message.len(), &mut buf_view).expect("correct length");
        let written_bytes = L - buf_view.len();

        let buf = &buf[..written_bytes];
        assert_eq!(buf, varint);
    }

    #[test]
    fn read_length_delimited_multiple_messages() {
        const FIRST: MessageAndLen<1, 5> = MessageAndLen::new([5], *b"12345");
        const SECOND: MessageAndLen<1, 7> = MessageAndLen::new([7], *b"abcdefg");
        const THIRD: MessageAndLen<2, 256> = MessageAndLen::new([0x80, 0x02], [0xab; 256]);

        // Assert that our constants are correct before using them as input to
        // the actual test.
        assert_valid(&FIRST);
        assert_valid(&SECOND);
        assert_valid(&THIRD);

        let concatenated_reader = FIRST
            .into_reader()
            .chain(SECOND.into_reader().chain(THIRD.into_reader()));
        let reader = VarintDelimitedReader::new(concatenated_reader);
        pin_mut!(reader);

        // Read two messages.
        assert_eq!(
            *block_on(reader.read_next())
                .expect("can read")
                .expect("has frame"),
            FIRST.message
        );
        assert_eq!(
            *block_on(reader.read_next())
                .expect("can read")
                .expect("has frame"),
            SECOND.message
        );
        assert_eq!(
            *block_on(reader.read_next())
                .expect("can read")
                .expect("has frame"),
            THIRD.message
        );
        assert_matches!(block_on(reader.read_next()), Ok(None));
    }
}
