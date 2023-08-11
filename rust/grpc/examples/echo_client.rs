use signal_grpc::{GrpcClient, Result};
use std::collections::HashMap;

struct SimpleListener {}

impl signal_grpc::GrpcReplyListener for SimpleListener {
    fn on_reply<'life0, 'async_trait>(
        &'life0 mut self,
        reply: signal_grpc::GrpcReply,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<()>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        println!("REPLY: {:?}", reply);
        Box::pin(async { Ok(()) })
    }

    fn on_error<'life0, 'async_trait>(
        &'life0 mut self,
        error: String,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<()>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        println!("REPLY_ERROR: {}", error);
        Box::pin(async { Ok(()) })
    }
}

fn main() -> Result<()> {
    let mut grpc_client = GrpcClient::new("https://grpcproxy.gluonhq.net:443".to_owned())?;

    let reply = grpc_client.echo_message("PING")?;
    println!("REPLY: {}", reply);

    let mut listener = SimpleListener {};

    let mut headers = HashMap::new();
    headers.insert("MK".to_owned(), vec!["Some meta info 101".to_owned()]);

    grpc_client.open_stream(
        "wss://signal7.gluonhq.net/time/".to_owned(),
        headers,
        &mut listener,
    )?;

    Ok(())
}
