import re

with open(r'd:\XIGUASecurity10x\antivirus-ui\src-tauri\src\scanner.rs', 'r', encoding='utf-8') as f:
    content = f.read()

# Find start: the comment before the ONNX function body
start = content.find('    // 运行ONNX模型推理 - 从 session pool 借用一个 session')
if start == -1:
    start = content.find('    fn run_tree_inference')

# Find end: the '    // 快速预检查' marker
end = content.find('    // 快速预检查 - 不运行模型', start)

if start != -1 and end != -1:
    replacement = '''    // 运行 TreeEnsemble 模型推理（纯 Rust，无 C++/ORT 依赖）
    fn run_tree_inference(&self, features: &[f32]) -> Result<f32, String> {
        let model_guard = self.tree_model.read()
            .map_err(|e| format!("Failed to lock tree model: {}", e))?;
        let model = model_guard.as_ref()
            .ok_or_else(|| "TreeEnsemble model not loaded".to_string())?;

        let output = model.evaluate(features);
        Ok(output.malicious_prob)
    }

    // 快速预检查 - 不运行模型'''
    content = content[:start] + replacement + content[end:]
    with open(r'd:\XIGUASecurity10x\antivirus-ui\src-tauri\src\scanner.rs', 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'Replaced {end - start} bytes from offset {start}')
else:
    print(f'start={start}, end={end}')
