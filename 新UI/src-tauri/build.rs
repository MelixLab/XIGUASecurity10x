fn main() {
    tauri_build::build();

    // 将 Driver 目录（Agent + 驱动）复制到编译输出目录（target/debug 或 target/release），
    // 使运行时可以在可执行文件同级找到 Driver/XIGUASecurityAgent.exe。
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let profile = std::env::var("PROFILE").expect("PROFILE");
    let src = std::path::Path::new(&manifest).join("Driver");
    let dst = std::path::Path::new(&manifest)
        .join("target")
        .join(&profile)
        .join("Driver");

    if src.is_dir() {
        let _ = std::fs::remove_dir_all(&dst);
        copy_dir(&src, &dst);
        println!("cargo:rerun-if-changed={}", src.display());
    }
}

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(src) {
        let _ = std::fs::create_dir_all(dst);
        for e in rd.flatten() {
            let p = e.path();
            let target = dst.join(e.file_name());
            if p.is_dir() {
                copy_dir(&p, &target);
            } else if p.is_file() {
                let _ = std::fs::copy(&p, &target);
            }
        }
    }
}
