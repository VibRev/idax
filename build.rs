//! Link against the IDA 9.4 install in `$IDADIR` (default: the installer's
//! location, `~/ida-pro-9.4`, the macOS app, or
//! `C:\Program Files\IDA Professional 9.4`). On Linux and macOS an rpath to
//! it lets the binary run without `LD_LIBRARY_PATH`; Windows has no rpath,
//! so there the install directory must be on `PATH` when idax runs. Without
//! an install the SDK's stub libraries link instead; such a binary builds and
//! passes clippy (CI does this) but does not run: the stubs are not IDA.
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
