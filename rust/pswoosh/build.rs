fn main() {
    cc::Build::new()
        .file("../../c-src/aesenc-int.c")
        .flag("-w")
        .flag("-march=native")
        .flag("-fomit-frame-pointer")
        .flag("-Wno-unused-function")
        .flag("-fwrapv")
        .flag("-fPIC")
        .flag("-fPIE")
        .compile("aesenc-int");

    cc::Build::new()
        .file("../../asm/fq.s")
        .flag("-march=native")
        .flag("-fomit-frame-pointer")
        .flag("-fPIC")
        .compile("fq");
}
