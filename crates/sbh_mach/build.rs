//! Compile the public Apple logging macro only for macOS targets.

fn main() {
    println!("cargo:rerun-if-changed=src/unified_log.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/unified_log.c")
            .warnings(true)
            .compile("sbh_unified_log");
    }
}
