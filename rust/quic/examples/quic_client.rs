use signal_quic::{QuicCallbackListener, QuicClient, Result};
use std::collections::HashMap;

struct SimpleListener {}

impl QuicCallbackListener for SimpleListener {
    fn on_data<'life0, 'async_trait>(
        &'life0 mut self,
        data: Vec<u8>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<()>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        println!("DATA: {:?}", data);
        Box::pin(async { Ok(()) })
    }
}

fn main() -> Result<()> {
    let mut grpc_client = QuicClient::new("localhost:7443".to_owned())?;

    let reply = grpc_client.send_message("PING".as_bytes())?;
    println!("REPLY: {:?}", reply);

    let mut listener = SimpleListener {};

    let mut headers = HashMap::new();
    headers.insert("MK".to_owned(), "Some meta info 101".to_owned());

    grpc_client.open_controlled_stream(
        "ws://localhost:8090/simple".to_owned(),
        headers,
        &mut listener,
    )?;

    Ok(())
}
