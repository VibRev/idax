//! Link against the IDA 9.4 install in `$IDADIR` (default `~/ida-pro-9.4`),
//! with an rpath to it so the binary runs without `LD_LIBRARY_PATH`. Without
//! an install the SDK's stub libraries link instead; such a binary builds and
//! tests its CLI but cannot open a database.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-env-changed=IDADIR");
    let (_, ida, idalib) = idalib_build::idalib_install_paths_with(false);
    if ida.exists() && idalib.exists() {
        idalib_build::configure_linkage()?;
    } else {
        println!("cargo::warning=no IDA install found (set IDADIR); linking the SDK stubs");
        idalib_build::configure_idasdk_linkage();
    }
    Ok(())
}
