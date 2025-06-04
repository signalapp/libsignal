fn main() {
    cc::Build::new()
        .file("./src/aesenc-int.c")
        .flag("-march=native")
        .flag("-fomit-frame-pointer")
        .flag("-Wno-unused-function")
        .flag("-fwrapv")
        .flag("-fPIC")
        .flag("-fPIE")
        .compile("aesenc-int");

    cc::Build::new()
        .file("./src/arithmetic/fq.s")
        .flag("-march=native")
        .flag("-fomit-frame-pointer")
        .flag("-fPIC")
        .compile("fq");
}
