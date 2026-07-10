use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by Cargo"));
    let manifest_path = out_dir.join("avorax-update-service-test.asinvoker.manifest");
    fs::write(
        &manifest_path,
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#,
    )
    .expect("write update-service test manifest");

    println!("cargo:rerun-if-changed=build.rs");
    for bin in [
        "avorax_generate_update_key",
        "avorax_sign_manifest",
        "avorax_update_service",
    ] {
        println!("cargo:rustc-link-arg-bin={bin}=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin={bin}=/MANIFESTINPUT:{}",
            manifest_path.display()
        );
    }
}
