fn main() {
    let protos = [
        "src/signal/proto/fingerprint.proto",
        "src/signal/proto/storage.proto",
        "src/signal/proto/wire.proto",
    ];
    prost_build::compile_protos(&protos, &["src"]).unwrap();
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
