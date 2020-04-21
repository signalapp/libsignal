fn main() {
    prost_build::compile_protos(&["src/signal/proto/transfer.proto"], &["src"]).unwrap();
    println!("cargo:rerun-if-changed=src/signal/proto/transfer.proto");
}
