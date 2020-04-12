use cc;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let hacl_path: PathBuf = Path::new("src/hacl").to_path_buf();
    let dist_path: PathBuf = hacl_path.join("c89-compatible");
    let kremlin_path: PathBuf = hacl_path.join("kremlin");

    let mut builder = cc::Build::new();
    builder.warnings_into_errors(true);
    builder.static_flag(true);
    builder.flag("-Wall");
    builder.flag("-Wextra");
    builder.flag("-Werror");
    builder.flag("-Wno-unused-variable");
    builder.flag("-Wno-unused-but-set-variable");
    builder.flag("-Wno-unused-parameter");
    builder.flag("-g");
    builder.flag("-fwrapv");
    builder.flag("-D_BSD_SOURCE");
    builder.flag("-D_DEFAULT_SOURCE");

    #[cfg(feature = "native")]
    {
        builder.flag("-march=native");
        builder.flag("-mtune=native");
    }

    // otherwise the default is some semi-old processor which supports AVX2 + AES-NI
    // which is needed for compilation, but which is not required at run-time due to feature detection.
    #[cfg(not(feature = "native"))]
    {
        builder.flag("-march=haswell");
        builder.flag("-mtune=haswell");
    }

    builder.flag("-std=gnu11");
    builder.include(&kremlin_path.join("include"));
    builder.include(&kremlin_path.join("kremlib/dist/minimal"));
    builder.include(&dist_path.join("include"));
    builder.include(&dist_path);

    // add platform dependent assembly
    let suffix = "-linux.S";
    for file in fs::read_dir(&dist_path).unwrap() {
        let file = file.unwrap();
        let name = file.file_name().into_string().unwrap();
        if name.ends_with(suffix) {
            builder.file(file.path());
        }
    }

    // build C code
    let suffix = ".c";
    for file in fs::read_dir(&dist_path).unwrap() {
        let file = file.unwrap();
        let name = file.file_name().into_string().unwrap();
        if name.ends_with(suffix) {
            builder.file(file.path());
        }
    }

    // compile to static library
    builder.compile("libevercrypt.a");
}
