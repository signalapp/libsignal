use signal_grpc::GrpcClient;

use signal_grpc::Result;

fn main() -> Result<()> {
    let mut grpc_client = GrpcClient::new()?;
    grpc_client.target("http://localhost:50051");

    let reply = grpc_client.echo_message("PING")?;

    println!("REPLY: {}", reply);

    Ok(())
}
