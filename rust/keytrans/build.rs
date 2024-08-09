fn main() {
    let protos = ["src/wire.proto"];
    let mut prost_build = prost_build::Config::new();
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    prost_build
        .compile_protos(&protos, &["src"])
        .expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
