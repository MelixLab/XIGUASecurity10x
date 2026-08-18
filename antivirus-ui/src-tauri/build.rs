fn main() {
    tauri_build::build();
    
    copy_virus_family_rules();
    // CARGO_FEATURE_MS_STORE 会在 --features ms_store 时自动设置为 "1"
    // MS Store 版本不复制驱动 YARA 规则
    if std::env::var("CARGO_FEATURE_MS_STORE").is_err() {
        copy_yara_rules();
    }
    copy_browser_extension();
}

fn copy_virus_family_rules() {
    use std::fs;
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let profile = std::env::var("PROFILE").unwrap_or("debug".to_string());

    // 项目根目录: antivirus-ui/ 的父目录
    let project_root = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to find project root");

    let rulers_source = project_root.join("rulers");
    if rulers_source.exists() {
        // 复制到 target/{profile}/rulers/ (exe 同级)
        let target_dir = Path::new(&manifest_dir)
            .join("target")
            .join(&profile)
            .join("rulers");

        if let Err(e) = fs::create_dir_all(&target_dir) {
            println!("cargo:warning=Failed to create rulers directory: {}", e);
        }

        if let Ok(entries) = fs::read_dir(&rulers_source) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    let dest = target_dir.join(path.file_name().unwrap());
                    if let Err(e) = fs::copy(&path, &dest) {
                        println!("cargo:warning=Failed to copy {:?}: {}", path, e);
                    } else {
                        println!("cargo:warning=Copied ruler: {:?}", path.file_name().unwrap());
                    }
                }
            }
        }
    } else {
        println!("cargo:warning=Rulers source directory not found: {:?}", rulers_source);
    }

    println!("cargo:rerun-if-changed=rulers/virus_family_rules.json");
}

fn copy_yara_rules() {
    use std::fs;
    use std::path::Path;
    
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let profile = std::env::var("PROFILE").unwrap_or("debug".to_string());
    
    let rules_source = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Driver").join("Rules"));
    
    if let Some(rules_source) = rules_source {
        if rules_source.exists() {
            let target_dir = Path::new(&manifest_dir)
                .join("target")
                .join(&profile)
                .join("Rules");
            
            if let Err(e) = fs::create_dir_all(&target_dir) {
                println!("cargo:warning=Failed to create Rules directory: {}", e);
            }
            
            if let Ok(entries) = fs::read_dir(&rules_source) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                        let dest = target_dir.join(path.file_name().unwrap());
                        if let Err(e) = fs::copy(&path, &dest) {
                            println!("cargo:warning=Failed to copy {:?}: {}", path, e);
                        } else {
                            println!("cargo:warning=Copied YARA rule: {:?}", path.file_name().unwrap());
                        }
                    }
                }
            }
            
            println!("cargo:rustc-env=YARA_RULES_DIR={}", target_dir.display());
        } else {
            println!("cargo:warning=YARA rules source directory not found: {:?}", rules_source);
        }
    }
    
    println!("cargo:rerun-if-changed=build.rs");
}

fn copy_browser_extension() {
    use std::fs;
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let profile = std::env::var("PROFILE").unwrap_or("debug".to_string());

    // 扩展源目录: 项目根目录/extensions/browser-protection（与 rulers/ 同级）
    let project_root = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to find project root");
    let ext_source = project_root.join("extensions").join("browser-protection");
    if !ext_source.exists() {
        println!("cargo:warning=Browser extension source not found: {:?}", ext_source);
        return;
    }

    // 复制到 target/{profile}/extensions/browser-protection/ (exe 同级)
    let target_dir = Path::new(&manifest_dir)
        .join("target")
        .join(&profile)
        .join("extensions")
        .join("browser-protection");

    if let Err(e) = fs::create_dir_all(&target_dir) {
        println!("cargo:warning=Failed to create extension directory: {}", e);
        return;
    }

    let files = ["manifest.json", "rules.json", "background.js", "popup.html", "popup.js", "blocked.html"];
    for file in &files {
        let src = ext_source.join(file);
        if src.exists() {
            let dest = target_dir.join(file);
            if let Err(e) = fs::copy(&src, &dest) {
                println!("cargo:warning=Failed to copy extension file {:?}: {}", file, e);
            }
        }
    }
    println!("cargo:warning=Copied browser extension to {:?}", target_dir);
    
    println!("cargo:rerun-if-changed=extensions/browser-protection/");
}
