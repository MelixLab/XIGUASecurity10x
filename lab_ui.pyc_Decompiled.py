# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'lab_ui.py'
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

"""HeySafe 沙箱实验室桌面壳（tkinter / PyInstaller 单文件）。"""
from __future__ import annotations
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
TIMEOUT_DEFAULT = 60
RUNTIME_MARK = 'runtime_v1'
NET_CHOICES = (('阻断外联（推荐）', 'block'), ('假网观察 C2', 'observe-c2'), ('允许真外联', 'allow-real'))
def app_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    else:
        return Path(__file__).resolve().parent.parent
def meipass() -> Path | None:
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS)
    else:
        return None
def runtime_dir() -> Path:
    local = Path(os.environ.get('LOCALAPPDATA') or str(app_dir()))
    d = local / 'HeySafeSandboxLab' / 'runtime'
    d.mkdir(parents=True, exist_ok=True)
    return d
def ensure_payload_extracted() -> Path:
    """单文件 exe：把内嵌引擎/DLL/Sandboxie 安装器抽到 %LOCALAPPDATA%。"""
    rt = runtime_dir()
    mark = rt / RUNTIME_MARK
    need = not mark.is_file() or not (rt / 'hsx-sandbox-lab.exe').is_file()
    src_root = meipass()
    if src_root is None:
        root = app_dir()
        for name in ['hsx-sandbox-lab.exe', 'hsx_timewarp.dll', 'sandman_block.exe']:
            for cand in [root / 'bin' / name, root / name, rt / name]:
                if cand.is_file() and cand.parent != rt:
                        shutil.copy2(cand, rt / name)
                        break
        sbie_src = None
        for d in [root / 'sbie', root]:
            if d.is_dir():
                found = sorted(d.glob('Sandboxie*.exe'), reverse=True)
                if found:
                    sbie_src = found[0]
                    break
        if sbie_src:
            (rt / 'sbie').mkdir(exist_ok=True)
            shutil.copy2(sbie_src, rt / 'sbie' / sbie_src.name)
        mark.write_text('ok', encoding='utf-8')
        return rt
    else:
        if need:
            payload = src_root / 'payload'
            if payload.is_dir():
                for p in payload.rglob('*'):
                    if p.is_file():
                        rel = p.relative_to(payload)
                        dst = rt / rel
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(p, dst)
            mark.write_text('ok', encoding='utf-8')
        return rt
def find_lab_exe() -> Path:
    rt = ensure_payload_extracted()
    for p in [rt / 'hsx-sandbox-lab.exe', app_dir() / 'bin' / 'hsx-sandbox-lab.exe', app_dir() / 'hsx-sandbox-lab.exe']:
        if p.is_file():
            return p
    return rt / 'hsx-sandbox-lab.exe'
def out_dir() -> Path:
    d = runtime_dir().parent / 'out'
    d.mkdir(parents=True, exist_ok=True)
    return d
def find_bundled_sbie_setup() -> Path | None:
    rt = ensure_payload_extracted()
    for base in [rt / 'sbie', app_dir() / 'sbie', app_dir()]:
        if not base.exists():
            continue
        else:
            if base.is_file() and 'sandboxie' in base.name.lower():
                return base
            else:
                cands = sorted([p for p in base.glob('*.exe') if 'sandboxie' in p.name.lower()], key=lambda p: p.name, reverse=True)
                if cands:
                    return cands[0]
def sbie_start_exists() -> bool:
    for p in [os.environ.get('HSX_SBIE_START') or '', 'C:\\Program Files\\Sandboxie-Plus\\Start.exe', 'C:\\Program Files\\Sandboxie\\Start.exe', 'C:\\Program Files (x86)\\Sandboxie-Plus\\Start.exe']:
        if p and Path(p).is_file():
                return True
    return False
def scrub_sandboxie_ui() -> None:
    """杀掉托盘 UI、改名禁用，并删除桌面/开始菜单快捷方式与 Run 自启。"""
    creation = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    for name in ['SandMan.exe', 'SbieCtrl.exe']:
        try:
            subprocess.run(['taskkill', '/IM', name, '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, creationflags=creation)
        except Exception:
            pass
    for base in [Path('C:\\Program Files\\Sandboxie-Plus'), Path('C:\\Program Files (x86)\\Sandboxie-Plus'), Path('C:\\Program Files\\Sandboxie'), Path('C:\\Program Files (x86)\\Sandboxie')]:
        for name in ['SandMan.exe', 'SbieCtrl.exe']:
            exe = base / name
            bak = base / f'{name}.bak'
            try:
                if exe.is_file() and (not bak.is_file()):
                        exe.rename(bak)
            except Exception:
                pass
    ps = '\n$ErrorActionPreference=\'SilentlyContinue\'\nforeach ($d in @(\n  [Environment]::GetFolderPath(\'Desktop\'),\n  [Environment]::GetFolderPath(\'CommonDesktopDirectory\'),\n  \"$env:PUBLIC\\Desktop\",\n  \"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\",\n  \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\"\n)) {\n  if (-not $d) { continue }\n  Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue |\n    Where-Object { $_.Name -match \'Sandboxie|SandMan|SbieCtrl\' } |\n    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue\n}\nforeach ($hive in @(\n  \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\',\n  \'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\',\n  \'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\'\n)) {\n  if (-not (Test-Path $hive)) { continue }\n  $props = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue\n  if (-not $props) { continue }\n  foreach ($n in @($props.PSObject.Properties.Name)) {\n    if ($n -match \'Sandboxie|SandMan|SbieCtrl\') {\n      Remove-ItemProperty -Path $hive -Name $n -Force -ErrorAction SilentlyContinue\n    }\n  }\n}\n'
    try:
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, creationflags=creation)
    except Exception:
        return None
def disable_sandman() -> None:
    scrub_sandboxie_ui()
def ensure_sandboxie(log_cb=None) -> bool:
    def log(msg: str) -> None:
        if log_cb:
            log_cb(msg)
    if sbie_start_exists():
        scrub_sandboxie_ui()
        return True
    else:
        setup = find_bundled_sbie_setup()
        if not setup:
            log('未找到内嵌/旁路 Sandboxie 安装器')
            return False
        else:
            log(f'正在安装内嵌 Sandboxie（请允许一次 UAC）:\n{setup}')
            try:
                messagebox.showinfo('安装运行环境', '首次使用需要安装沙箱驱动（包内自带，无需另下）。\n请在弹出的 UAC 中点「是」。')
            except Exception:
                pass
            setup_s = str(setup).replace('\'', '\'\'')
            ps = f'$p = Start-Process -FilePath \'{setup_s}\' -ArgumentList \'/VERYSILENT\',\'/NORESTART\',\'/SUPPRESSMSGBOXES\',\'/NOICONS\',\'/TASKS=\' -Wait -PassThru -Verb RunAs; exit $p.ExitCode'
            r = subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], capture_output=True, text=True, encoding='utf-8', errors='replace')
            if r.returncode != 0:
                log(f'安装失败 exit={r.returncode}（若取消了 UAC 请重试）')
                return False
            else:
                time.sleep(2)
                scrub_sandboxie_ui()
                ok = sbie_start_exists()
                log('沙箱环境已就绪' if ok else '安装后仍找不到 Start.exe')
                if ok:
                    os.environ['HSX_SBIE_START'] = 'C:\\Program Files\\Sandboxie-Plus\\Start.exe'
                return ok
FAMILY_ZH = {'none': '无', 'None': '无', 'silver_fox': '银狐', 'SilverFox': '银狐', 'destructive': '破坏型/勒索', 'Destructive': '破坏型/勒索', 'generic_malware': '通用恶意软件', 'GenericMalware': '通用恶意软件'}
KIND_ZH = {'benign': ('未检出威胁', '#1B7A3D'), 'Benign': ('未检出威胁', '#1B7A3D'), 'suspicious': ('行为可疑', '#B86B00'), 'Suspicious': ('行为可疑', '#B86B00'), 'malicious': ('检出威胁', '#C62828'), 'Malicious': ('检出威胁', '#C62828')}
def format_verdict(kind: str, family: str) -> tuple[str, str]:
    """返回 (展示文案, 颜色)。"""
    label, color = KIND_ZH.get(kind, (str(kind), '#333333'))
    fam = FAMILY_ZH.get(family, family if family and family != 'None' else '无')
    if kind in ['benign', 'Benign']:
        return (f'结论：{label}\n家族：无', color)
    else:
        return (f'结论：{label}\n家族：{fam}', color)
class LabApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title('HeySafe 沙箱实验室')
        self.geometry('720x420')
        self.minsize(640, 360)
        self._proc = None
        self._q = queue.Queue()
        self._net_label = tk.StringVar(value=NET_CHOICES[0][0])
        self._build()
        self.after(120, self._drain)
        self.after(200, self._bootstrap)
    def _build(self) -> None:
        pad = {'padx': 10, 'pady': 6}
        top = ttk.Frame(self)
        top.pack(fill=tk.X, **pad)
        ttk.Label(top, text='样本路径').pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8)
        ttk.Button(top, text='浏览…', command=self._browse).pack(side=tk.LEFT)
        row = ttk.Frame(self)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text='超时(秒)').pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value=str(TIMEOUT_DEFAULT))
        ttk.Entry(row, width=8, textvariable=self.timeout_var).pack(side=tk.LEFT, padx=6)
        ttk.Label(row, text='网络').pack(side=tk.LEFT, padx=(16, 4))
        ttk.Combobox(row, width=18, state='readonly', textvariable=self._net_label, values=tuple((x[0] for x in NET_CHOICES))).pack(side=tk.LEFT)
        btns = ttk.Frame(self)
        btns.pack(fill=tk.X, **pad)
        self.run_btn = ttk.Button(btns, text='开始分析', command=self._run)
        self.run_btn.pack(side=tk.LEFT)
        ttk.Button(btns, text='停止', command=self._stop).pack(side=tk.LEFT, padx=8)
        self.status = tk.StringVar(value='就绪')
        ttk.Label(self, textvariable=self.status).pack(anchor=tk.W, padx=10)
        self.result = tk.Label(self, text='选择样本后点击「开始分析」', font=('Microsoft YaHei UI', 22, 'bold'), justify=tk.CENTER, fg='#333333')
        self.result.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    def _net_flag(self) -> str:
        label = self._net_label.get()
        for zh, en in NET_CHOICES:
            if zh == label:
                return en
        return 'block'
    def _browse(self) -> None:
        p = filedialog.askopenfilename(title='选择样本', filetypes=[('可执行/安装包', '*.exe;*.msi;*.dll;*.bat;*.cmd;*.ps1'), ('全部', '*.*')])
        if p:
            self.path_var.set(p)
    def _append(self, line: str) -> None:
        self.status.set(line[:120] if line else self.status.get())
    def _drain(self) -> None:
        # irreducible cflow, using cdg fallback
        # ***<module>.LabApp._drain: Failure: Compilation Error
            msg = self._q.get_nowait()
            if msg.startswith('RESULT|'):
                parts = msg.split('|', 2)
                if len(parts) >= 3:
                    text, color = format_verdict(parts[1], parts[2])
                    self.result.configure(text=text, fg=color)
            else:
                if msg.startswith('STATUS|'):
                    self.status.set(msg[7:])
                else:
                    if msg.startswith('ERR|'):
                        self.result.configure(text=msg[4:], fg='#C62828')
                        self.status.set('失败')
            except queue.Empty:
                except queue.Empty:
                    pass
        pass
        pass
        self.after(120, self._drain)
    def _set_busy(self, busy: bool) -> None:
        self.run_btn.configure(state=tk.DISABLED if busy else tk.NORMAL)
        self.status.set('分析中，请稍候…' if busy else '就绪')
    def _bootstrap(self) -> None:
        def work() -> None:
            try:
                ensure_payload_extracted()
                ensure_sandboxie(lambda m: self._q.put('STATUS|' + m))
            except Exception as e:
                self._q.put(f'STATUS|引导失败: {e}')
        threading.Thread(target=work, daemon=True).start()
    def _run(self) -> None:
        sample = self.path_var.get().strip().strip('\"')
        if not sample or not Path(sample).is_file():
            messagebox.showwarning('提示', '请先选择有效的样本文件')
            return
        else:
            if not ensure_sandboxie(lambda m: self._q.put('STATUS|' + m)):
                messagebox.showwarning('提示', '沙箱环境未就绪，请允许 UAC 安装包内驱动后重试。')
                return
            else:
                exe = find_lab_exe()
                if not exe.is_file():
                    messagebox.showerror('错误', f'找不到引擎：{exe}')
                    return
                else:
                    try:
                        timeout = max(5, int(self.timeout_var.get().strip()))
                    except ValueError:
                        messagebox.showwarning('提示', '超时秒数无效')
                        return
                    cmd = [str(exe), 'run', sample, '--timeout-secs', str(timeout), '--out-dir', str(out_dir())]
                    net = self._net_flag()
                    if net == 'observe-c2':
                        cmd.append('--observe-c2')
                    else:
                        if net == 'allow-real':
                            cmd.append('--allow-net')
                    self.result.configure(text='正在分析…', fg='#555555')
                    self._spawn_analysis(cmd)
    def _stop(self) -> None:
        if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                self._q.put('STATUS|已请求停止')
    def _spawn_analysis(self, cmd: list[str]) -> None:
        # ***<module>.LabApp._spawn_analysis: Failure: Different bytecode
        if self._proc and self._proc.poll() is None:
            messagebox.showinfo('提示', '已有任务在运行')
            return
        else:
            self._set_busy(True)
            def worker() -> None:
                # ***<module>.LabApp._spawn_analysis.worker: Failure: Compilation Error
                try:
                    creation = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if sys.platform == 'win32' else 0
                    self._proc = subprocess.Popen(cmd, cwd=str(find_lab_exe().parent), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=creation, env={**os.environ})
                    assert self._proc.stdout is not None
                    for _line in self._proc.stdout:
                        continue
                    code = self._proc.wait()
                    if code != 0:
                        self._q.put('ERR|分析失败，请换样本重试')
                    else:
                        self._emit_verdict()
                except Exception as e:
                    self._q.put(f'ERR|分析出错：{e}')
                finally:
                    self._proc = None
                    self.after(0, lambda /: self._set_busy(False))
            threading.Thread(target=worker, daemon=True).start()
    def _emit_verdict(self) -> None:
        od = out_dir()
        candidates = []
        for p in od.glob('*.json'):
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
            except Exception:
                pass
            else:
                if isinstance(data, dict) and 'verdict' in data:
                        candidates.append((p.stat().st_mtime, p, data))
        if not candidates:
            self._q.put('ERR|未生成结果')
            return
        else:
            candidates.sort(key=lambda x: x[0], reverse=True)
            data = candidates[0][2]
            v = data.get('verdict') or {}
            kind = str(v.get('kind') or '?')
            family = str(v.get('family') or 'None')
            self._q.put(f'RESULT|{kind}|{family}')
def _crash_log(msg: str) -> Path:
    p = app_dir() / 'ui-crash.txt'
    try:
        p.write_text(msg, encoding='utf-8')
    except Exception:
        pass
    return p
def main() -> None:
    try:
        ensure_payload_extracted()
    except Exception:
        pass
    try:
        scrub_sandboxie_ui()
    except Exception:
        pass
    try:
        app = LabApp()
        app.mainloop()
    except Exception as e:
        import traceback
        log = _crash_log(traceback.format_exc())
        try:
            messagebox.showerror('启动失败', f'{e}\n\n详情已写入:\n{log}')
        except Exception:
            pass
        raise
if __name__ == '__main__':
    main()