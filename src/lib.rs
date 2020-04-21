pub(crate) mod signal;

#[cfg(test)]
mod test {
    use super::signal::proto::transfer::SignalMessage;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn proto_test() {
        let m = SignalMessage::default();
        assert_eq!(m.counter, 0);
    }
}
