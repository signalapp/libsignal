//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implementation of the Noise Direct framing protocol.

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::num::NonZeroU8;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use assert_matches::assert_matches;
use bytes::Bytes;
use futures_util::Stream;
use futures_util::sink::Sink;
use futures_util::stream::FusedStream;
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zerocopy::{FromBytes, IntoBytes};

use crate::noise::{FrameType, HandshakeAuthKind, Transport};
use crate::proto::noise_direct::CloseReason;
use crate::proto::noise_direct::close_reason::Code;

/// Implements the Noise Direct framing protocol on top of a reliable byte
/// stream.
#[derive(Debug)]
pub struct DirectStream<S> {
    inner: S,
    read: Option<Read>,
    write: Option<Write>,
}

impl<S> DirectStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read: Some(Read::Pending),
            write: Some(Write::Pending),
        }
    }
}

static_assertions::assert_impl_all!(DirectStream<tokio::io::DuplexStream>: Transport);

/// State for the [`AsyncRead`] side of a [`DirectStream`].
#[derive(Debug, Default)]
enum Read {
    /// No read is currently in progress.
    #[default]
    Pending,
    /// A frame is in the process of being reassembled.
    Partial(ReadingFrame),
}

#[derive(Debug)]
struct PartialFrame {
    frame_type: FrameOrClose,
    bytes_read: u16,
    // Invariant: bytes_read <= payload_buffer.len() <= u16::MAX
    payload_buffer: Box<[u8]>,
}

#[derive(Debug)]
enum ReadingFrame {
    /// The header is being read
    Header {
        buffer: [u8; Header::LEN],
        bytes_read: NonZeroU8,
    },
    /// The header is available and the payload is being read.
    Payload(PartialFrame),
}

#[derive(Debug)]
enum Write {
    Pending,
    Partial {
        writing: WritingFrame,
        flush_after: bool,
        close_after: bool,
    },
    Flushing {
        close_after: bool,
    },
    ShuttingDown {
        close_frame: Option<WritingFrame>,
    },
}

#[derive(Debug)]
enum WritingFrame {
    WriteHeader {
        header: Header,
        written_bytes: u8,
        payload: Bytes,
    },
    WritePayload(Bytes),
}

/// A Noise Direct frame header as read off the wire.
#[derive(
    Debug, zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable,
)]
#[repr(C)]
struct Header {
    /// 4 reserved bits plus the type of the frame.
    frame_type: u8,
    payload_length: zerocopy::big_endian::U16,
}

enum WriteState {
    Quiesced,
    FinishedClose,
}

impl Header {
    const LEN: usize = std::mem::size_of::<Header>();
}
static_assertions::const_assert_eq!(Header::LEN, 3);

#[derive(Copy, Clone, Debug, displaydoc::Display, derive_more::From)]
enum FrameOrClose {
    /// {0}
    Frame(#[from] FrameType),
    /// close
    Close,
}

impl FrameOrClose {
    const NK: u8 = 1;
    const IK: u8 = 2;
    const DATA: u8 = 3;
    const CLOSE: u8 = 4;

    const fn parse(frame_type: u8) -> Option<Self> {
        Some(match frame_type {
            Self::NK => Self::Frame(FrameType::Auth(HandshakeAuthKind::NK)),
            Self::IK => Self::Frame(FrameType::Auth(HandshakeAuthKind::IK)),
            Self::DATA => Self::Frame(FrameType::Data),
            Self::CLOSE => Self::Close,
            _ => return None,
        })
    }

    const fn as_byte(&self) -> u8 {
        match self {
            Self::Frame(FrameType::Data) => Self::DATA,
            Self::Frame(FrameType::Auth(HandshakeAuthKind::IK)) => Self::IK,
            Self::Frame(FrameType::Auth(HandshakeAuthKind::NK)) => Self::NK,
            Self::Close => Self::CLOSE,
        }
    }
}

impl<S: AsyncRead + Unpin> Stream for DirectStream<S> {
    type Item = Result<Bytes, IoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            inner,
            read,
            write: _,
        } = &mut *self;

        let Some(read) = read.as_mut() else {
            return Poll::Ready(None);
        };

        let maybe_finished = match read {
            Read::Pending => {
                let partial = ready!(ReadingFrame::start_read(inner, cx))?;
                let Some(partial) = partial else {
                    self.read = None;
                    return Poll::Ready(None);
                };
                *read = Read::Partial(partial);
                assert_matches!(read, Read::Partial(partial) => partial, "just set")
            }
            Read::Partial(partial) => {
                ready!(partial.poll_read(inner, cx))?;
                partial
            }
        };

        // We're in the process of reading a frame.
        let PartialFrame {
            frame_type,
            bytes_read,
            payload_buffer,
        } = match maybe_finished {
            ReadingFrame::Header { .. } => return Poll::Pending,
            ReadingFrame::Payload(payload) => payload,
        };
        if usize::from(*bytes_read) != payload_buffer.len() {
            return Poll::Pending;
        }

        // The payload is finished being read; now handle the completed frame.

        let payload = Bytes::from(std::mem::take(payload_buffer));
        let close_frame = match frame_type {
            FrameOrClose::Frame(FrameType::Auth(_)) => {
                // The server shouldn't be sending auth frames since it's not
                // initiating the connection. It should only be sending data
                // frames, including in response to our auth frames.
                return Poll::Ready(Some(Err(IoError::other("received unexpected auth frame"))));
            }
            FrameOrClose::Frame(FrameType::Data) => {
                *read = Read::Pending;

                return Poll::Ready(Some(Ok(payload)));
            }
            FrameOrClose::Close => {
                // Close frame has a protobuf message payload.
                CloseReason::decode(payload).map_err(|e| {
                    log::debug!("close frame was not a valid protobuf: {e}");
                    IoError::other("protobuf decode error")
                })?
            }
        };

        let CloseReason { code, message } = close_frame;
        let code = Code::try_from(code).ok();

        Poll::Ready(match code {
            None | Some(Code::Unspecified) => {
                Some(Err(IoError::other(format!("invalid close code {code:?}"))))
            }
            Some(Code::Ok) => None,
            Some(Code::Unavailable) => {
                // The server is shutting down gracefully. We can just treat this as a normal close.
                log::info!("noise direct server is becoming unavailable; shutting down gracefully");
                None
            }
            Some(code @ (Code::HandshakeError | Code::EncryptionError | Code::InternalError)) => {
                log::debug!("server closed with error {code:?} ({message:?})");
                Some(Err(IoError::other(format!(
                    "server closed with error: {code:?}"
                ))))
            }
        })
    }
}

impl<S: AsyncRead + Unpin> FusedStream for DirectStream<S> {
    fn is_terminated(&self) -> bool {
        self.read.is_none()
    }
}

impl<S: AsyncWrite + Unpin> Sink<(FrameType, Bytes)> for DirectStream<S> {
    type Error = IoError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Self {
            write,
            inner,
            read: _,
        } = &mut *self;
        let write = write.as_mut().ok_or(StreamClosed)?;

        match ready!(write.poll(inner, cx))? {
            WriteState::Quiesced => Poll::Ready(Ok(())),
            WriteState::FinishedClose => {
                self.write = None;
                Poll::Ready(Err(StreamClosed.into()))
            }
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        (frame_type, payload): (FrameType, Bytes),
    ) -> Result<(), Self::Error> {
        let Self {
            write,
            inner: _,
            read: _,
        } = &mut *self;
        let write = write.as_mut().ok_or(StreamClosed)?;

        match write {
            Write::Pending => {
                log::trace!(
                    "starting send of {}-byte {} frame",
                    payload.len(),
                    frame_type
                );
                *write = Write::Partial {
                    writing: WritingFrame::new(frame_type.into(), payload),
                    flush_after: false,
                    close_after: false,
                };
                Ok(())
            }
            Write::ShuttingDown { close_frame: _ } | Write::Flushing { close_after: true } => {
                Err(StreamClosed.into())
            }
            Write::Partial {
                writing: _,
                flush_after: _,
                close_after: _,
            }
            | Write::Flushing { close_after: false } => Err(IoError::new(
                IoErrorKind::ResourceBusy,
                "send already in progress",
            )),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Self {
            write,
            inner,
            read: _,
        } = &mut *self;
        let write = write.as_mut().ok_or(StreamClosed)?;
        match write {
            Write::Pending => return Poll::Ready(Ok(())),
            Write::Partial {
                flush_after,
                writing: _,
                close_after: _,
            } => {
                *flush_after = true;
            }
            Write::Flushing { close_after: _ } | Write::ShuttingDown { close_frame: _ } => (),
        }

        match ready!(write.poll(inner, cx))? {
            WriteState::Quiesced => Poll::Ready(Ok(())),
            WriteState::FinishedClose => {
                self.write = None;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Self {
            write,
            inner,
            read: _,
        } = &mut *self;
        let Some(write) = write else {
            return Poll::Ready(Ok(()));
        };

        match write {
            Write::Pending => {
                *write = Write::ShuttingDown {
                    close_frame: Some(WritingFrame::new_close()),
                };
            }
            Write::Partial { close_after, .. } | Write::Flushing { close_after } => {
                if !*close_after {
                    log::trace!("setting shutdown flag");
                }
                *close_after = true;
            }
            Write::ShuttingDown { close_frame: _ } => (),
        }

        match ready!(write.poll(inner, cx))? {
            WriteState::Quiesced | WriteState::FinishedClose => {
                self.write = None;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl Write {
    fn poll(
        &mut self,
        mut inner: &mut (impl AsyncWrite + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<WriteState, IoError>> {
        match self {
            Write::Pending => Poll::Ready(Ok(WriteState::Quiesced)),
            Write::Partial {
                writing,
                flush_after,
                close_after,
            } => {
                let () = ready!(writing.poll_write(inner, cx))?;
                if *flush_after {
                    log::trace!("write completed; starting flush");
                    *self = Write::Flushing {
                        close_after: *close_after,
                    };
                    return self.poll(inner, cx);
                }

                if *close_after {
                    log::trace!("write completed; starting close frame");
                    *self = Write::ShuttingDown {
                        close_frame: Some(WritingFrame::new_close()),
                    };
                    return self.poll(inner, cx);
                }

                *self = Write::Pending;
                Poll::Ready(Ok(WriteState::Quiesced))
            }
            Write::Flushing { close_after } => {
                let () = ready!(Pin::new(&mut inner).poll_flush(cx))?;

                if *close_after {
                    log::trace!("flush completed; starting close frame");
                    *self = Write::ShuttingDown {
                        close_frame: Some(WritingFrame::new_close()),
                    };
                    return self.poll(inner, cx);
                }

                log::trace!("flush completed");
                *self = Write::Pending;
                Poll::Ready(Ok(WriteState::Quiesced))
            }
            Write::ShuttingDown {
                close_frame: Some(writing),
            } => {
                let () = ready!(writing.poll_write(inner, cx))?;
                *self = Write::ShuttingDown { close_frame: None };
                log::trace!("writing close frame completed");
                self.poll(inner, cx)
            }

            Write::ShuttingDown { close_frame: None } => {
                let () = ready!(Pin::new(inner).poll_shutdown(cx))?;
                log::trace!("shutdown complete");
                Poll::Ready(Ok(WriteState::FinishedClose))
            }
        }
    }
}

struct StreamClosed;

impl From<StreamClosed> for IoError {
    fn from(StreamClosed: StreamClosed) -> Self {
        IoError::new(IoErrorKind::BrokenPipe, "the stream is closed")
    }
}

impl ReadingFrame {
    /// Read a partial frame from the provided stream.
    ///
    /// Returns `None` if EOF is read (successful read of 0 bytes).
    fn start_read(
        mut inner: &mut (impl AsyncRead + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self>, IoError>> {
        let mut buffer = [0; Header::LEN];
        let mut read_buf = ReadBuf::new(&mut buffer);
        let () = ready!(Pin::new(&mut inner).poll_read(cx, &mut read_buf))?;
        let read = read_buf.filled();

        if read.is_empty() {
            log::trace!("got EOF instead of next header");
            return Poll::Ready(Ok(None));
        }

        log::trace!("read {} bytes of next frame", read.len());

        let mut reading = if read_buf.remaining() != 0 {
            let bytes_read = NonZeroU8::new(read.len().try_into().expect("buffer is small"))
                .expect("read is not empty");
            log::trace!("have {} of {} header bytes", bytes_read, buffer.len());

            Self::Header { bytes_read, buffer }
        } else {
            Self::Payload(PartialFrame::new_from_header(buffer)?)
        };

        match reading.poll_read(inner, cx)? {
            // As long as the read after didn't fail, return the new in-progress read.
            Poll::Ready(()) | Poll::Pending => Poll::Ready(Ok(Some(reading))),
        }
    }

    fn poll_read(
        &mut self,
        mut inner: &mut (impl AsyncRead + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), IoError>> {
        match self {
            ReadingFrame::Header { buffer, bytes_read } => {
                // Keep attempting to make progress; when `inner.poll_read`
                // returns `Pending` it will also register our context's waker
                // to be notified when more bytes are available.
                let mut read_buf = ReadBuf::new(buffer);
                read_buf.advance(bytes_read.get().into());

                let result = loop {
                    let filled_before = read_buf.filled().len();
                    match Pin::new(&mut inner).poll_read(cx, &mut read_buf)? {
                        Poll::Pending => break Poll::Pending,
                        Poll::Ready(()) => (),
                    }

                    let read_len = read_buf.filled().len() - filled_before;
                    if read_len == 0 {
                        return Poll::Ready(Err(IoError::new(
                            IoErrorKind::UnexpectedEof,
                            "header was too short",
                        )));
                    }

                    log::trace!("read {read_len} bytes of frame header");

                    if read_buf.remaining() == 0 {
                        break Poll::Ready(());
                    }
                };

                *bytes_read =
                    NonZeroU8::new(u8::try_from(read_buf.filled().len()).expect("buffer is small"))
                        .expect("starts with >0 filled bytes");
                let () = ready!(result);

                *self = Self::Payload(PartialFrame::new_from_header(*buffer)?);

                self.poll_read(inner, cx)
            }
            ReadingFrame::Payload(partial) => partial.poll_read(inner, cx),
        }
    }
}

impl PartialFrame {
    fn new_from_header(header: [u8; Header::LEN]) -> Result<Self, IoError> {
        let Header {
            frame_type,
            payload_length,
        } = Header::ref_from_bytes(&header).expect("correct size");

        let frame_type = FrameOrClose::parse(*frame_type)
            .ok_or_else(|| IoError::other(format!("unexpected frame type 0x{frame_type:X}")))?;

        log::trace!("read header for {payload_length}-byte {frame_type} frame");
        Ok(Self {
            frame_type,
            bytes_read: 0,
            payload_buffer: vec![0; payload_length.get().into()].into_boxed_slice(),
        })
    }

    fn poll_read(
        &mut self,
        inner: &mut (impl AsyncRead + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), IoError>> {
        let Self {
            frame_type: _,
            payload_buffer,
            bytes_read,
        } = self;
        if payload_buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(inner);
        let mut read_buf = ReadBuf::new(payload_buffer);
        read_buf.advance((*bytes_read).into());

        // Continue trying to make progress until the inner `poll_read` returns `Pending`.
        // That ensures that our context's waker will get notified the next time
        // there are more bytes to read.
        let result = loop {
            let filled_before = read_buf.filled().len();
            match inner.as_mut().poll_read(cx, &mut read_buf)? {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(()) => (),
            };

            let read_count = read_buf.filled().len() - filled_before;
            if read_count == 0 {
                return Poll::Ready(Err(IoError::new(
                    IoErrorKind::UnexpectedEof,
                    "frame was too short",
                )));
            }

            log::trace!(
                "read {read_count} bytes; have {} of {}-byte payload",
                read_buf.filled().len(),
                read_buf.capacity()
            );

            if read_buf.remaining() == 0 {
                break Poll::Ready(Ok(()));
            }
        };
        *bytes_read = u16::try_from(read_buf.filled().len()).expect("blocks are small");
        result
    }
}

impl WritingFrame {
    fn new(frame_type: FrameOrClose, payload: Bytes) -> Self {
        Self::WriteHeader {
            header: Header {
                frame_type: frame_type.as_byte(),
                payload_length: payload.len().try_into().expect("small enough"),
            },
            written_bytes: 0,
            payload,
        }
    }

    /// Ahead-of-time serialized [`CloseReason`] with code `Code::Ok`.
    const CLOSE_PAYLOAD: [u8; 2] = [0x08, 0x01];

    fn new_close() -> WritingFrame {
        Self::WriteHeader {
            header: Header {
                frame_type: FrameOrClose::CLOSE,
                payload_length: Self::CLOSE_PAYLOAD.len().try_into().unwrap(),
            },
            written_bytes: 0,
            payload: Bytes::from_static(&Self::CLOSE_PAYLOAD),
        }
    }

    fn poll_write(
        &mut self,
        mut inner: &mut (impl AsyncWrite + Unpin),
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), IoError>> {
        match self {
            WritingFrame::WriteHeader {
                header,
                written_bytes,
                payload,
            } => {
                // Continue trying to make progress until the inner `poll_write`
                // returns `Pending`. That ensures that our context's waker will
                // get notified the next time there is more space to write.
                let mut unwritten_header = &header.as_bytes()[usize::from(*written_bytes)..];
                let result = loop {
                    let written = match Pin::new(&mut inner).poll_write(cx, unwritten_header)? {
                        Poll::Ready(written) => written,
                        Poll::Pending => break Poll::Pending,
                    };
                    log::trace!("wrote {written} bytes of header");
                    unwritten_header = &unwritten_header[written..];

                    if unwritten_header.is_empty() {
                        break Poll::Ready(());
                    }
                };
                *written_bytes =
                    u8::try_from(Header::LEN - unwritten_header.len()).expect("small header");

                let () = ready!(result);
                log::trace!(
                    "writing header finished; now writing the {}-byte payload",
                    payload.len()
                );
                *self = WritingFrame::WritePayload(std::mem::take(payload));
                self.poll_write(inner, cx)
            }
            WritingFrame::WritePayload(bytes) => {
                while !bytes.is_empty() {
                    // Continue trying to make progress until the inner `poll_write`
                    // returns `Pending`. That ensures that our context's waker will
                    // get notified the next time there is more space to write.
                    let written = ready!(Pin::new(&mut inner).poll_write(cx, bytes))?;
                    let _ = bytes.split_to(written);
                    log::trace!(
                        "wrote {written} bytes of payload; {} remaining",
                        bytes.len()
                    );
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::pin::pin;

    use const_str::concat_bytes;
    use futures_util::future::try_join;
    use futures_util::{FutureExt, SinkExt, StreamExt as _, TryStreamExt as _};
    use prost::Message;
    use test_case::test_case;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt};

    use super::*;
    use crate::proto::noise_direct::CloseReason;
    use crate::proto::noise_direct::close_reason::Code;

    #[test_log::test]
    fn reads_frame_as_it_comes_in() {
        const PAYLOAD: &[u8] = b"NK handshake payload";

        // Leave only enough space for the payload to assert that the header
        // bytes were pulled out.
        let (read, mut write) = tokio::io::simplex(PAYLOAD.len());
        let mut direct = DirectStream::new(read);

        // No bytes written yet
        assert_matches!(direct.next().now_or_never(), None);

        write
            .write_all(&[FrameOrClose::DATA, 0x00, 0x14])
            .now_or_never()
            .expect("finished")
            .expect("can write");

        // The header has been read but there isn't a frame available.
        assert_matches!(direct.next().now_or_never(), None);

        write
            .write_all(PAYLOAD)
            .now_or_never()
            .expect("finished")
            .expect("can write");

        let payload = direct
            .next()
            .now_or_never()
            .expect("ready")
            .expect("has frame")
            .expect("not an error");

        assert_eq!(payload, Bytes::from_static(PAYLOAD));
    }

    #[test_log::test]
    fn reads_whole_frame_if_available() {
        const PAYLOAD: &[u8] = b"payload";

        let mut direct = DirectStream::new(
            Cursor::new([FrameOrClose::DATA, 0x00, 0x7]).chain(Cursor::new(PAYLOAD)),
        );

        let payload = direct
            .next()
            .now_or_never()
            .expect("ready")
            .expect("has frame")
            .expect("not an error");

        assert_eq!(payload, Bytes::from_static(PAYLOAD));
    }

    #[test_log::test]
    fn reads_multiple_frames() {
        let mut direct = DirectStream::new(Cursor::new(*concat_bytes!(
            [FrameOrClose::DATA, 0x00, 0x01, b'a'],
            [FrameOrClose::DATA, 0x00, 0x01, b'b'],
            [FrameOrClose::DATA, 0x00, 0x01, b'c']
        )));

        let frames = (&mut direct)
            .try_collect::<Vec<_>>()
            .now_or_never()
            .unwrap()
            .expect("no error");
        assert_eq!(
            frames,
            [
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
            ]
        );

        assert!(direct.is_terminated(), "{direct:?}");
    }

    #[test_log::test]
    fn read_invalid_frame_type() {
        let mut direct = DirectStream::new(Cursor::new([0x05, 0x00, 0x7]));

        let err = direct
            .next()
            .now_or_never()
            .expect("finished")
            .expect("has result")
            .expect_err("invalid frame type");
        assert!(err.to_string().contains("frame type"), "{err}");
    }

    #[test_case(1; "reading header")]
    #[test_case(3; "after header")]
    #[test_case(5; "in frame body")]
    fn read_unexpected_eof_within_frame(truncate_to: u64) {
        const INPUT: [u8; 7] = *concat_bytes!([FrameOrClose::DATA, 0x00, 0x04], *b"data");
        let mut stream = DirectStream::new(Cursor::new(INPUT).take(truncate_to));

        // We might need to poll a few times to get to the read that returns EOF.
        let finished = stream
            .next()
            .now_or_never()
            .or_else(|| stream.next().now_or_never())
            .expect("finished");

        let err = finished.expect("has result").expect_err("EOF error");
        assert_eq!(err.kind(), IoErrorKind::UnexpectedEof);
    }

    #[test_log::test]
    fn read_frame_with_empty_payload() {
        // Even if this isn't expected in practice, it's nice to know what the behavior is.
        let mut direct = DirectStream::new(Cursor::new([FrameOrClose::DATA, 0x00, 0x00]));

        let payload = direct
            .next()
            .now_or_never()
            .expect("finished")
            .expect("has result")
            .expect("valid frame");

        assert_eq!(payload, Bytes::new());
    }

    #[test_case(Code::Ok; "ok")]
    #[test_case(Code::Unavailable; "server unavailable")]
    fn read_close_frame_clean_exit(code: Code) {
        let payload = CloseReason {
            code: code.into(),
            ..Default::default()
        }
        .encode_to_vec();
        let mut stream = DirectStream::new(
            Cursor::new([FrameOrClose::CLOSE, 0x00, payload.len().try_into().unwrap()])
                .chain(Cursor::new(payload)),
        );

        assert_matches!(stream.next().now_or_never(), Some(None));
    }

    #[test_case(Code::Unspecified; "unspecified")]
    #[test_case(Code::HandshakeError; "handshake error")]
    #[test_case(Code::EncryptionError; "encryption error")]
    #[test_case(Code::InternalError; "internal error")]
    fn read_close_frame_unclean_exit(code: impl Into<i32>) {
        let payload = CloseReason {
            code: code.into(),
            ..Default::default()
        }
        .encode_to_vec();
        let mut stream = DirectStream::new(
            Cursor::new([FrameOrClose::CLOSE, 0x00, payload.len().try_into().unwrap()])
                .chain(Cursor::new(payload)),
        );

        let err = stream
            .next()
            .now_or_never()
            .expect("finished")
            .expect("has next")
            .expect_err("unclean close");
        assert_eq!(err.kind(), IoErrorKind::Other);
    }

    #[test_log::test]
    fn write_frame_piece_by_piece() {
        // Leave only enough space for the payload to assert that the header
        // bytes were pulled out.
        let (read, write) = tokio::io::simplex(Header::LEN);
        let mut read = pin!(read);
        let mut direct = DirectStream::new(write);

        // No bytes written yet.
        let mut buffer = [0; 60];
        assert_matches!(read.read(&mut buffer).now_or_never(), None);

        const PAYLOAD: &[u8] = b"payload larger than one header";

        let () = direct
            .feed((FrameType::Data, Bytes::from_static(PAYLOAD)))
            .now_or_never()
            .expect("can send")
            .expect("no error");

        let mut flush = direct.flush();

        assert_matches!((&mut flush).now_or_never(), None);

        // The header should have made it to the read end.
        assert_matches!(read.read(&mut buffer).now_or_never(), Some(Ok(Header::LEN)));

        // With another round, the first bytes of the payload should too.
        assert_matches!((&mut flush).now_or_never(), None);
        assert_matches!(
            read.read(&mut buffer[Header::LEN..]).now_or_never(),
            Some(Ok(Header::LEN))
        );

        let ((), count) = 'outer: {
            let mut read =
                pin!(read.read_exact(&mut buffer[Header::LEN..][Header::LEN..PAYLOAD.len()]));

            // try_join with .now_or_never() isn't as eager to try to make
            // progress as we'd like so just poll in a loop to make sure
            // progress is being made.
            for _ in 0..10 {
                if let Some(x) = try_join(&mut flush, &mut read).now_or_never() {
                    break 'outer x;
                }
            }
            panic!("didn't finish")
        }
        .expect("no error");

        assert_eq!(count, PAYLOAD.len() - Header::LEN);
        assert_eq!(&buffer[Header::LEN..][..PAYLOAD.len()], PAYLOAD);
    }

    #[test_log::test]
    fn writes_whole_frame_if_possible() {
        const PAYLOAD: &[u8] = b"abcde";
        let (read, write) = tokio::io::simplex(Header::LEN + PAYLOAD.len());
        let mut read = pin!(read);
        let mut direct = DirectStream::new(write);

        let () = direct
            .send((HandshakeAuthKind::IK.into(), Bytes::from_static(PAYLOAD)))
            .now_or_never()
            .expect("finishes")
            .expect("no error");

        let mut buffer = [0; PAYLOAD.len() + Header::LEN];
        assert_eq!(
            read.read_exact(&mut buffer)
                .now_or_never()
                .expect("finishes")
                .expect("no error"),
            Header::LEN + PAYLOAD.len()
        );

        let (header, payload) = buffer.split_at(Header::LEN);
        assert_eq!(header, &[FrameOrClose::IK, 0x00, 0x05]);
        assert_eq!(payload, PAYLOAD);
    }

    #[test_log::test]
    fn writes_multiple_frames_before_close() {
        let (read, write) = tokio::io::simplex(60);
        let mut read = pin!(read);
        let mut direct = DirectStream::new(write);

        direct
            .send_all(
                &mut futures_util::stream::iter([
                    (HandshakeAuthKind::IK.into(), Bytes::from_static(b"a")),
                    (FrameType::Data, Bytes::from_static(b"b")),
                    (HandshakeAuthKind::NK.into(), Bytes::from_static(b"c")),
                ])
                .map(Ok),
            )
            .now_or_never()
            .expect("finished")
            .expect("success");

        direct
            .close()
            .now_or_never()
            .expect("finished")
            .expect("success");

        let mut buffer = Vec::new();
        read.read_to_end(&mut buffer)
            .now_or_never()
            .expect("finished")
            .expect("success");

        let expected = *concat_bytes!(
            [FrameOrClose::IK, 0x00, 0x01, b'a'],
            [FrameOrClose::DATA, 0x00, 0x01, b'b'],
            [FrameOrClose::NK, 0x00, 0x01, b'c'],
            [FrameOrClose::CLOSE, 0x00, 0x02],
            WritingFrame::CLOSE_PAYLOAD
        );

        assert_eq!(&buffer, &expected);
    }

    #[test_log::test]
    fn write_then_close_still_writes() {
        const PAYLOAD: &[u8] = b"abcde";
        // The simplex's buffer is small enough that the entire frame won't fit
        // at once.
        let (read, write) = tokio::io::simplex(Header::LEN);
        let mut read = pin!(read);
        let mut direct = DirectStream::new(write);

        let () = direct
            .feed((HandshakeAuthKind::IK.into(), Bytes::from_static(PAYLOAD)))
            .now_or_never()
            .expect("finishes")
            .expect("no error");

        let mut close = direct.close();

        let mut buffer =
            [0; (PAYLOAD.len() + Header::LEN) + (WritingFrame::CLOSE_PAYLOAD.len() + Header::LEN)];
        let ((), count) = 'outer: {
            let mut read = pin!(read.read_exact(&mut buffer));

            // try_join with .now_or_never() isn't as eager to try to make
            // progress as we'd like so just poll in a loop to make sure
            // progress is being made.
            for _ in 0..10 {
                if let Some(x) = try_join(&mut close, &mut read).now_or_never() {
                    break 'outer x;
                }
            }
            panic!("didn't finish")
        }
        .expect("no error");

        assert_eq!(count, buffer.len());
        let (frame, _close) = buffer.split_at(Header::LEN + PAYLOAD.len());
        {
            let (header, payload) = frame.split_at(Header::LEN);
            assert_eq!(header, &[FrameOrClose::IK, 0x00, 0x05]);
            assert_eq!(payload, PAYLOAD);
        }
    }

    /// If the underlying stream only allows writing a small number of bytes at
    /// a time, the provided blocks should still make it through after
    /// fragmentation and reassembly.
    #[test_case::test_matrix([1, 2, 3, 4])]
    #[test_log::test(tokio::test)]
    async fn read_write_over_fragmenting_channel(channel_size: usize) {
        let (read, write) = tokio::io::simplex(channel_size);

        let (read, mut write) = (DirectStream::new(read), DirectStream::new(write));

        const FRAMES: [&[u8]; 3] = [
            b"some fragmented frames",
            b"split into many pieces",
            b"collected again",
        ];

        // Send only data frames because `DirectStream` is a client implementation and
        // only the server receives Auth frames.
        let mut items = futures_util::stream::repeat(FrameType::Data)
            .zip(futures_util::stream::iter(FRAMES.map(Bytes::from_static)))
            .map(Ok);
        let write_fut = async move {
            write.send_all(&mut items).await?;
            write.close().await
        };

        let read_fut = read.try_collect();

        let ((), received): (_, Vec<_>) = try_join(write_fut, read_fut).await.unwrap();

        assert_eq!(received, FRAMES);
    }

    #[test]
    fn static_close_frame_is_correct_protobuf_message() {
        assert_eq!(
            WritingFrame::CLOSE_PAYLOAD,
            *CloseReason {
                code: Code::Ok.into(),
                message: String::default(),
            }
            .encode_to_vec()
        )
    }
}
