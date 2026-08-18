#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XIGUASecurity Hash Extractor
从指定目录提取文件哈希并生成白名单/黑名单 JSON 文件
"""

import sys
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
    QProgressBar, QMessageBox, QGroupBox, QSpinBox, QTabWidget,
    QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class HashCalculator:
    """哈希计算器"""
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """计算文件哈希值"""
        try:
            if algorithm == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm == 'md5':
                hasher = hashlib.md5()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            with open(file_path, 'rb') as f:
                # 分块读取大文件
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest().lower()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None


class ExtractionWorker(QThread):
    """后台提取工作线程"""
    
    progress_updated = pyqtSignal(int, int, str)  # 当前进度, 总数, 当前文件
    hash_calculated = pyqtSignal(str, str)  # 文件路径, 哈希值
    finished_signal = pyqtSignal(list)  # 结果列表
    error_occurred = pyqtSignal(str)
    
    def __init__(self, directory: str, max_workers: int = 4):
        super().__init__()
        self.directory = directory
        self.max_workers = max_workers
        self.is_running = True
        
    def run(self):
        try:
            # 获取所有文件
            files = []
            for root, _, filenames in os.walk(self.directory):
                if not self.is_running:
                    return
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    files.append(file_path)
            
            total = len(files)
            results = []
            
            # 使用线程池并行计算哈希
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(HashCalculator.calculate_file_hash, file_path): file_path
                    for file_path in files
                }
                
                completed = 0
                for future in as_completed(future_to_file):
                    if not self.is_running:
                        return
                    
                    file_path = future_to_file[future]
                    try:
                        file_hash = future.result()
                        if file_hash:
                            results.append({
                                'file_path': file_path,
                                'hash': file_hash,
                                'file_name': os.path.basename(file_path)
                            })
                            self.hash_calculated.emit(file_path, file_hash)
                    except Exception as e:
                        self.error_occurred.emit(f"Error processing {file_path}: {e}")
                    
                    completed += 1
                    self.progress_updated.emit(completed, total, file_path)
            
            self.finished_signal.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def stop(self):
        self.is_running = False


class WhiteListTab(QWidget):
    """白名单提取标签页"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.extracted_hashes = []
        self.worker = None
        self.parent_window = parent
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # 说明标签
        desc_label = QLabel('提取目录中所有文件的哈希值，生成白名单 JSON 文件（用于程序规则）')
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet('color: #666; padding: 10px; background-color: #f0f0f0; border-radius: 5px;')
        layout.addWidget(desc_label)
        
        # 结果显示
        result_group = QGroupBox('提取结果')
        result_layout = QVBoxLayout(result_group)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText('点击"开始提取"按钮开始扫描...')
        result_layout.addWidget(self.result_text)
        
        layout.addWidget(result_group)
        
        # 导出按钮
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton('导出白名单 JSON')
        self.export_btn.setStyleSheet('background-color: #2196F3; color: white; padding: 10px; font-weight: bold;')
        self.export_btn.clicked.connect(self.export_json)
        self.export_btn.setEnabled(False)
        btn_layout.addWidget(self.export_btn)

        self.export_txt_btn = QPushButton('导出平台 TXT')
        self.export_txt_btn.setStyleSheet('background-color: #107c10; color: white; padding: 10px; font-weight: bold;')
        self.export_txt_btn.clicked.connect(self.export_txt)
        self.export_txt_btn.setEnabled(False)
        btn_layout.addWidget(self.export_txt_btn)

        layout.addLayout(btn_layout)
        
        # 统计信息
        self.stats_label = QLabel('已提取: 0 个哈希')
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.stats_label)
    
    def on_hash_calculated(self, file_path: str, file_hash: str):
        self.extracted_hashes.append({
            'file_path': file_path,
            'hash': file_hash,
            'file_name': os.path.basename(file_path)
        })
        self.result_text.append(f'{file_hash} - {os.path.basename(file_path)}')
        self.stats_label.setText(f'已提取: {len(self.extracted_hashes)} 个哈希')
    
    def on_extraction_finished(self):
        self.export_btn.setEnabled(True)
        self.export_txt_btn.setEnabled(True)
        QMessageBox.information(self, '完成', f'成功提取 {len(self.extracted_hashes)} 个文件的哈希值')
    
    def clear_results(self):
        self.extracted_hashes = []
        self.result_text.clear()
        self.export_btn.setEnabled(False)
        self.export_txt_btn.setEnabled(False)
        self.stats_label.setText('已提取: 0 个哈希')
    
    def export_json(self):
        if not self.extracted_hashes:
            QMessageBox.warning(self, '警告', '没有可导出的哈希数据')
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, '保存白名单 JSON', f'whitelist_{datetime.now().strftime("%Y%m%d")}.json', 
            'JSON Files (*.json)'
        )
        
        if not file_path:
            return
        
        try:
            # 构建白名单数据结构 - 与主程序格式兼容
            hashes = sorted(list(set([item['hash'] for item in self.extracted_hashes])))
            file_names = sorted(list(set([item['file_name'] for item in self.extracted_hashes])))
            
            whitelist_data = {
                'version': '1.0.0',
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f'Generated from {self.parent_window.dir_input.text() if self.parent_window else "unknown"}',
                'file_hashes': hashes,
                'file_names': file_names
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(whitelist_data, f, indent=2, ensure_ascii=False)
            
            QMessageBox.information(self, '成功', f'白名单已保存到:\n{file_path}')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败: {e}')

    def export_txt(self):
        if not self.extracted_hashes:
            QMessageBox.warning(self, '警告', '没有可导出的哈希数据')
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, '保存平台格式白名单 TXT', f'whitelist_{datetime.now().strftime("%Y%m%d")}.txt',
            'Text Files (*.txt)'
        )
        if not file_path:
            return

        try:
            hashes = sorted(list(set([item['hash'] for item in self.extracted_hashes])))
            lines = [f"{h},0" for h in hashes]
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            QMessageBox.information(self, '成功', f'平台格式白名单已保存到:\n{file_path}\n共 {len(lines)} 条')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败: {e}')


class BlackListTab(QWidget):
    """黑名单提取标签页"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.extracted_hashes = []
        self.worker = None
        self.parent_window = parent
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # 说明标签
        desc_label = QLabel('提取病毒文件哈希，生成黑名单 JSON 文件（用于云端哈希库）')
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet('color: #666; padding: 10px; background-color: #fff3e0; border-radius: 5px;')
        layout.addWidget(desc_label)
        
        # 病毒家族设置
        family_group = QGroupBox('病毒家族设置')
        family_layout = QHBoxLayout(family_group)
        
        family_layout.addWidget(QLabel('默认病毒家族:'))
        self.family_combo = QComboBox()
        self.family_combo.setEditable(True)
        self.family_combo.addItems([
            'Trojan.Win32.Generic',
            'Worm.Win32.AutoRun',
            'Ransomware.Win32.Crypto',
            'Backdoor.Win32.Remote',
            'Spyware.Win32.Keylogger',
            'Adware.Win32.Generic',
            'Rootkit.Win32.Hidden',
            'Virus.Win32.Parite',
            'Unknown.Malware'
        ])
        self.family_combo.setCurrentText('Trojan.Win32.Generic')
        self.family_combo.setMinimumWidth(300)
        family_layout.addWidget(self.family_combo)
        family_layout.addStretch()
        
        layout.addWidget(family_group)
        
        # 结果显示
        result_group = QGroupBox('提取结果')
        result_layout = QVBoxLayout(result_group)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setPlaceholderText('点击"开始提取"按钮开始扫描病毒文件...')
        result_layout.addWidget(self.result_text)
        
        layout.addWidget(result_group)
        
        # 导出按钮
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton('导出黑名单 JSON')
        self.export_btn.setStyleSheet('background-color: #f44336; color: white; padding: 10px; font-weight: bold;')
        self.export_btn.clicked.connect(self.export_json)
        self.export_btn.setEnabled(False)
        btn_layout.addWidget(self.export_btn)

        self.export_txt_btn = QPushButton('导出平台 TXT')
        self.export_txt_btn.setStyleSheet('background-color: #107c10; color: white; padding: 10px; font-weight: bold;')
        self.export_txt_btn.clicked.connect(self.export_txt)
        self.export_txt_btn.setEnabled(False)
        btn_layout.addWidget(self.export_txt_btn)

        layout.addLayout(btn_layout)
        
        # 统计信息
        self.stats_label = QLabel('已提取: 0 个黑哈希')
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.stats_label)
    
    def on_hash_calculated(self, file_path: str, file_hash: str):
        self.extracted_hashes.append({
            'file_path': file_path,
            'hash': file_hash,
            'file_name': os.path.basename(file_path)
        })
        family = self.family_combo.currentText()
        self.result_text.append(f'{file_hash},{family} - {os.path.basename(file_path)}')
        self.stats_label.setText(f'已提取: {len(self.extracted_hashes)} 个黑哈希')
    
    def on_extraction_finished(self):
        self.export_btn.setEnabled(True)
        self.export_txt_btn.setEnabled(True)
        QMessageBox.information(self, '完成', f'成功提取 {len(self.extracted_hashes)} 个病毒文件哈希')

    def clear_results(self):
        self.extracted_hashes = []
        self.result_text.clear()
        self.export_btn.setEnabled(False)
        self.export_txt_btn.setEnabled(False)
        self.stats_label.setText('已提取: 0 个黑哈希')
    
    def export_json(self):
        if not self.extracted_hashes:
            QMessageBox.warning(self, '警告', '没有可导出的哈希数据')
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, '保存黑名单 JSON', f'blacklist_{datetime.now().strftime("%Y%m%d")}.json', 
            'JSON Files (*.json)'
        )
        
        if not file_path:
            return
        
        try:
            # 构建黑名单数据结构 - 与云端哈希库格式兼容
            default_family = self.family_combo.currentText()
            entries = []
            
            for item in self.extracted_hashes:
                entries.append({
                    'hash': item['hash'],
                    'family': default_family,
                    'file_name': item['file_name'],
                    'file_path': item['file_path']
                })
            
            blacklist_data = {
                'version': '1.0.0',
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f'Black hashes generated from {self.parent_window.dir_input.text() if self.parent_window else "unknown"}',
                'type': 'blacklist',
                'entries': entries,
                'total_count': len(entries)
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(blacklist_data, f, indent=2, ensure_ascii=False)
            
            QMessageBox.information(self, '成功', f'黑名单已保存到:\n{file_path}\n\n包含 {len(entries)} 个黑哈希，默认家族: {default_family}')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败: {e}')

    def export_txt(self):
        if not self.extracted_hashes:
            QMessageBox.warning(self, '警告', '没有可导出的哈希数据')
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, '保存平台格式黑名单 TXT', f'blacklist_{datetime.now().strftime("%Y%m%d")}.txt',
            'Text Files (*.txt)'
        )
        if not file_path:
            return

        try:
            family = self.family_combo.currentText()
            # 去重：相同 hash 只保留一条
            seen = set()
            lines = []
            for item in self.extracted_hashes:
                h = item['hash']
                if h not in seen:
                    seen.add(h)
                    lines.append(f"{h},1,{family}")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            QMessageBox.information(self, '成功', f'平台格式黑名单已保存到:\n{file_path}\n共 {len(lines)} 条，家族: {family}')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'保存失败: {e}')


class HashExtractorWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('XIGUASecurity Hash Extractor - 哈希提取工具')
        self.setMinimumSize(900, 700)
        
        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # 标题
        title_label = QLabel('XIGUASecurity 哈希提取工具')
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet('font-size: 20px; font-weight: bold; margin-bottom: 10px; color: #333;')
        layout.addWidget(title_label)
        
        subtitle_label = QLabel('支持白名单（程序规则）和黑名单（云端哈希库）提取')
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet('font-size: 12px; color: #666; margin-bottom: 15px;')
        layout.addWidget(subtitle_label)
        
        # 目录选择组
        dir_group = QGroupBox('选择目录')
        dir_layout = QHBoxLayout(dir_group)
        
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText('请选择要扫描的目录...')
        dir_layout.addWidget(self.dir_input)
        
        browse_btn = QPushButton('浏览...')
        browse_btn.setStyleSheet('padding: 5px 15px;')
        browse_btn.clicked.connect(self.browse_directory)
        dir_layout.addWidget(browse_btn)
        
        layout.addWidget(dir_group)
        
        # 设置组
        settings_group = QGroupBox('设置')
        settings_layout = QHBoxLayout(settings_group)
        
        settings_layout.addWidget(QLabel('并发线程数:'))
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 16)
        self.thread_spin.setValue(4)
        settings_layout.addWidget(self.thread_spin)
        
        settings_layout.addStretch()
        
        layout.addWidget(settings_group)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton('开始提取')
        self.start_btn.setStyleSheet('background-color: #4CAF50; color: white; padding: 12px; font-weight: bold; font-size: 14px;')
        self.start_btn.clicked.connect(self.start_extraction)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton('停止')
        self.stop_btn.setStyleSheet('background-color: #f44336; color: white; padding: 12px; font-weight: bold; font-size: 14px;')
        self.stop_btn.clicked.connect(self.stop_extraction)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet('QProgressBar { border: 1px solid #ccc; border-radius: 5px; height: 25px; }')
        layout.addWidget(self.progress_bar)
        
        # 状态标签
        self.status_label = QLabel('就绪 - 请选择目录并点击"开始提取"')
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet('color: #666; padding: 5px;')
        layout.addWidget(self.status_label)
        
        # 标签页
        self.tab_widget = QTabWidget()
        
        # 白名单标签页
        self.white_tab = WhiteListTab(self)
        self.tab_widget.addTab(self.white_tab, '白名单提取')
        
        # 黑名单标签页
        self.black_tab = BlackListTab(self)
        self.tab_widget.addTab(self.black_tab, '黑名单提取')
        
        layout.addWidget(self.tab_widget)
        
    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, '选择目录')
        if directory:
            self.dir_input.setText(directory)
    
    def start_extraction(self):
        directory = self.dir_input.text().strip()
        if not directory:
            QMessageBox.warning(self, '警告', '请先选择要扫描的目录')
            return
        
        if not os.path.exists(directory):
            QMessageBox.warning(self, '警告', '选择的目录不存在')
            return
        
        # 清空两个标签页的结果
        self.white_tab.clear_results()
        self.black_tab.clear_results()
        
        self.progress_bar.setValue(0)
        
        self.worker = ExtractionWorker(directory, self.thread_spin.value())
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.hash_calculated.connect(self.on_hash_calculated)
        self.worker.finished_signal.connect(self.on_extraction_finished)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText('正在提取...')
        self.status_label.setStyleSheet('color: #2196F3; padding: 5px; font-weight: bold;')
    
    def stop_extraction(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText('已停止')
        self.status_label.setStyleSheet('color: #f44336; padding: 5px;')
    
    def update_progress(self, current: int, total: int, file_path: str):
        percentage = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percentage)
        self.status_label.setText(f'正在处理: {current}/{total} - {os.path.basename(file_path)}')
    
    def on_hash_calculated(self, file_path: str, file_hash: str):
        # 同时更新两个标签页的结果
        self.white_tab.on_hash_calculated(file_path, file_hash)
        self.black_tab.on_hash_calculated(file_path, file_hash)
    
    def on_extraction_finished(self, results: list):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f'提取完成！共 {len(results)} 个文件')
        self.status_label.setStyleSheet('color: #4CAF50; padding: 5px; font-weight: bold;')
        
        # 通知两个标签页提取完成
        self.white_tab.on_extraction_finished()
        self.black_tab.on_extraction_finished()
    
    def on_error(self, error_msg: str):
        QMessageBox.critical(self, '错误', f'提取过程中发生错误:\n{error_msg}')


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # 设置应用程序样式
    app.setStyleSheet('''
        QMainWindow {
            background-color: #f5f5f5;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #cccccc;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QPushButton {
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }
        QPushButton:hover {
            opacity: 0.8;
        }
        QPushButton:disabled {
            background-color: #cccccc;
        }
        QLineEdit, QTextEdit {
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        }
        QProgressBar {
            border: 1px solid #cccccc;
            border-radius: 4px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #4CAF50;
            border-radius: 3px;
        }
        QTabWidget::pane {
            border: 1px solid #cccccc;
            border-radius: 5px;
            background-color: white;
        }
        QTabBar::tab {
            padding: 10px 20px;
            margin-right: 2px;
            border: 1px solid #cccccc;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            background-color: #e0e0e0;
        }
        QTabBar::tab:selected {
            background-color: white;
            border-bottom: 2px solid #2196F3;
        }
        QComboBox {
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
            min-width: 200px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            border: 1px solid #cccccc;
            selection-background-color: #2196F3;
        }
    ''')
    
    window = HashExtractorWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
