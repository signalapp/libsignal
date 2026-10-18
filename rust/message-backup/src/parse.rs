//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use arrayvec::ArrayVec;
use futures::io::{AsyncRead, AsyncReadExt as _};

const VARINT_MAX_LENGTH: usize = 10;

/// The most that will be allocated for a frame before any of its contents have been read.
const MAX_PREALLOCATED_FRAME_LEN: usize = 64 * 1024;

pub struct VarintDelimitedReader<R> {
    reader: R,
    buffer: ArrayVec<u8, VARINT_MAX_LENGTH>,
}

impl<R: AsyncRead + Unpin> VarintDelimitedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: ArrayVec::new(),
        }
    }

    pub async fn read_next(&mut self) -> Result<Option<Box<[u8]>>, std::io::Error> {
        self.read_next_with_max_len(usize::MAX).await
    }

    /// Like [`Self::read_next`], but fails with [`std::io::ErrorKind::InvalidData`] if the next
    /// frame is longer than `max_len`.
    pub async fn read_next_with_max_len(
        &mut self,
        max_len: usize,
    ) -> Result<Option<Box<[u8]>>, std::io::Error> {
        let length = match self.read_next_varint().await? {
            None => return Ok(None),
            Some(length) => length,
        };

        if length > max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame length {length} exceeds maximum of {max_len}"),
            ));
        }

        let Self { reader, buffer } = self;

        // Read `length` bytes, first from the buffer, then from the reader.
        let mut buf = Vec::with_capacity(length.min(MAX_PREALLOCATED_FRAME_LEN));
        let buffered_byte_count = length.min(buffer.len());
        buf.extend_from_slice(&buffer[..buffered_byte_count]);
        buffer.drain(..buffered_byte_count);

        // The length hasn't been checked against the actual input yet, so grow the buffer only as
        // bytes arrive. Otherwise a short input claiming a huge frame forces a huge allocation.
        while buf.len() < length {
            let start = buf.len();
            let end = length.min(start.saturating_mul(2).max(MAX_PREALLOCATED_FRAME_LEN));
            buf.resize(end, 0);

            reader.read_exact(&mut buf[start..]).await?;
        }

        Ok(Some(buf.into_boxed_slice()))
    }

    /// Consumes self, returning the inner [`AsyncRead`]er.
    pub fn into_inner(self) -> R {
        assert!(
            self.buffer.is_empty(),
            "would lose data to convert to the inner reader"
        );
        self.reader
    }

    async fn read_next_varint(&mut self) -> Result<Option<usize>, std::io::Error> {
        let Self { buffer, reader } = self;

        fill_buffer_from_reader(reader, buffer).await?;

        if buffer.is_empty() {
            return Ok(None);
        }

        let mut proto_reader = protobuf::CodedInputStream::from_bytes(buffer);

        let length = proto_reader.read_raw_varint32()?;

        // Remove the consumed bytes from the buffer.
        let consumed_byte_count: usize =
            proto_reader.pos().try_into().expect("< VARINT_MAX_LENGTH");
        drop(proto_reader);

        buffer.drain(..consumed_byte_count);

        Ok(Some(length.try_into().expect("u32::MAX < usize::MAX")))
    }
}

/// Read bytes from `reader` into `buffer`.
///
/// Returns when the latter is full or the former is exhausted.
async fn fill_buffer_from_reader<R: AsyncRead + Unpin, const N: usize>(
    reader: &mut R,
    buffer: &mut ArrayVec<u8, N>,
) -> Result<(), std::io::Error> {
    // First fill up the buffer with zeros so it can be treated as a slice.
    // Keep track of how many bytes in the buffer have actually been read
    // from the reader.
    let mut valid_bytes = buffer.len();
    buffer.extend(
        [0; VARINT_MAX_LENGTH][..buffer.remaining_capacity()]
            .iter()
            .cloned(),
    );
    while valid_bytes < buffer.len() {
        let n = reader.read(&mut buffer[valid_bytes..]).await?;
        if n == 0 {
            break;
        }
        valid_bytes += n;
    }
    buffer.truncate(valid_bytes);
    Ok(())
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
            let mut writer = protobuf::CodedOutputStream::bytes(&mut short_buf);
            writer
                .write_raw_varint32(MESSAGE_SIZE.try_into().unwrap())
                .expect("can hold varint");
            writer.flush().expect("can write");
            assert_eq!(
                writer.total_bytes_written(),
                u64::try_from(VARINT_LEN).unwrap()
            );
        }

        let reader = VarintDelimitedReader::new(short_buf.as_slice());
        pin_mut!(reader);

        assert_matches!(
            block_on(reader.read_next()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        );
    }
    #[test]
    fn read_length_delimited_huge_length_truncated() {
        // A length of u32::MAX with no message following it must not allocate
        // based on the claimed length.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        let reader = VarintDelimitedReader::new(bytes.as_slice());
        pin_mut!(reader);

        assert_matches!(
            block_on(reader.read_next()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn read_length_delimited_larger_than_preallocation() {
        let message = vec![0xab; MAX_PREALLOCATED_FRAME_LEN * 3 + 1];
        let mut bytes = Vec::new();
        {
            let mut writer = protobuf::CodedOutputStream::vec(&mut bytes);
            writer
                .write_raw_varint32(message.len().try_into().unwrap())
                .expect("can write");
            writer.flush().expect("can write");
        }
        bytes.extend_from_slice(&message);

        let reader = VarintDelimitedReader::new(bytes.as_slice());
        pin_mut!(reader);

        assert_eq!(
            *block_on(reader.read_next())
                .expect("can read")
                .expect("has frame"),
            *message
        );
        assert_matches!(block_on(reader.read_next()), Ok(None));
    }

    #[test]
    fn read_length_delimited_exceeds_max_len() {
        let bytes = [5, b'h', b'e', b'l', b'l', b'o'];

        let reader = VarintDelimitedReader::new(bytes.as_slice());
        pin_mut!(reader);
        assert_matches!(
            block_on(reader.read_next_with_max_len(4)),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData
        );

        let reader = VarintDelimitedReader::new(bytes.as_slice());
        pin_mut!(reader);
        assert_eq!(
            *block_on(reader.read_next_with_max_len(5))
                .expect("can read")
                .expect("has frame"),
            *b"hello"
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
        let mut writer = protobuf::CodedOutputStream::bytes(&mut buf);
        writer
            .write_raw_varint32(message.len().try_into().unwrap())
            .expect("correct length");
        writer.flush().expect("can write");
        let written_bytes = writer.total_bytes_written().try_into().unwrap();
        drop(writer);

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

    #[derive(Debug)]
    struct ForbidZeroLengthTargetReader<R>(R);

    impl<R: AsyncRead + Unpin> AsyncRead for ForbidZeroLengthTargetReader<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if buf.is_empty() {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "zero-length read is forbidden",
                )));
            }
            std::pin::Pin::new(&mut self.as_mut().0).poll_read(cx, buf)
        }
    }

    /// Regression test for a behavior where VarintDelimitedReader was calling
    /// `AsyncRead::read` with an empty slice.
    #[test]
    fn varint_read_with_empty_target_slice() {
        const FIRST: MessageAndLen<1, 9> = MessageAndLen::new([9], *b"123456789");
        const SECOND: MessageAndLen<1, 7> = MessageAndLen::new([7], *b"abcdefg");

        // Assert that our constants are correct before using them as input to
        // the actual test.
        assert_valid(&FIRST);
        assert_valid(&SECOND);

        let concatenated_reader = FIRST.into_reader().chain(SECOND.into_reader());
        let reader = VarintDelimitedReader::new(ForbidZeroLengthTargetReader(concatenated_reader));
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
        assert_matches!(block_on(reader.read_next()), Ok(None));
    }
}
