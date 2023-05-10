use signal_grpc::GrpcClient;

use signal_grpc::Result;

fn main() -> Result<()> {
    let grpc_client = GrpcClient::new()?;

    let reply = grpc_client.echo_message("PING")?;

    println!("REPLY: {}", reply);

    Ok(())
}
