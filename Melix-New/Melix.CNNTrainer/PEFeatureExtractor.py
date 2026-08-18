# Copyright (C) 2026 LinduCMint
"""PE 文件特征提取器 - 基于完整 PE 文件，提取结构特征（优化版）"""

import os
import re
import math
import hashlib
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional
import numpy as np


class PEFeatureExtractor:
    """从完整 PE 文件提取结构特征"""

    SUSPICIOUS_DLLS = {
        'kernel32', 'ntdll', 'user32', 'wininet', 'ws2_32', 'urlmon',
        'shell32', 'advapi32', 'crypt32', 'cryptbase', 'bcrypt',
        'netapi32', 'winhttp', 'msvcrt', 'ole32', 'oleaut32'
    }

    SUSPICIOUS_APIS = {
        'virtualalloc', 'virtualprotect', 'heapalloc', 'loadlibrary',
        'getprocaddress', 'createremotethread', 'writeprocessmemory',
        'openprocess', 'ntunmapviewofsection', 'ntwritevirtualmemory',
        'internetopen', 'internetconnect', 'httpopenrequest', 'httpaddrequestheaders',
        'urldownloadtofile', 'winexec', 'createprocess', 'shellexecute',
        'regopenkey', 'regsetvalue', 'createfile', 'writefile', 'readfile',
        'mapviewoffile', 'unhookwindowshookex', 'setwindowshookex',
        'cryptencrypt', 'cryptdecrypt', 'cryptimportkey', 'rc4',
        'memcpy', 'memset', 'strcat', 'strcpy', 'sprintf', 'wsprintf',
        'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
        'gettickcount', 'queryperformancecounter', 'sleep'
    }

    SUSPICIOUS_SECTIONS = {
        '.upx', '.vmp', '.vmps', '.aspack', '.petite', '.themida',
        'upx0', 'upx1', 'upx2', '.data1', '.text1', '.adata', '.adata1'
    }

    RT_TYPES = {
        1: 'cursor', 2: 'bitmap', 3: 'icon', 4: 'menu', 5: 'dialog',
        6: 'string', 7: 'fontdir', 8: 'font', 9: 'accelerator',
        10: 'rcdata', 11: 'messagetable', 12: 'group_cursor',
        14: 'group_icon', 16: 'version', 19: 'plugplay',
        20: 'vxd', 21: 'anicursor', 22: 'aniicon', 24: 'manifest'
    }

    def __init__(self, max_file_size: int = 10 * 1024 * 1024):
        self.max_file_size = max_file_size
        self.feature_names = self._build_feature_names()
        # 关闭 lief 日志
        try:
            import lief
            lief.logging.disable()
        except Exception:
            pass

    def _build_feature_names(self) -> List[str]:
        names = []
        names.append('file_size')
        names.append('file_entropy')
        names.append('is_pe')
        names.append('is_dll')
        names.append('is_64bit')
        names.append('pe_offset')
        names.append('machine')
        names.append('subsystem')
        names.append('timestamp')
        names.append('image_base')
        names.append('entry_point')
        names.append('code_base')
        names.append('section_alignment')
        names.append('file_alignment')
        names.append('size_of_image')
        names.append('size_of_headers')
        names.append('checksum')
        names.append('dll_characteristics')
        names.append('number_of_sections')

        names.extend([f'section_{i}_virtual_size' for i in range(10)])
        names.extend([f'section_{i}_raw_size' for i in range(10)])
        names.extend([f'section_{i}_entropy' for i in range(10)])
        names.extend([f'section_{i}_is_executable' for i in range(10)])
        names.extend([f'section_{i}_is_writable' for i in range(10)])
        names.extend([f'section_{i}_name_hash' for i in range(10)])

        names.append('sections_max_entropy')
        names.append('sections_min_entropy')
        names.append('sections_mean_entropy')
        names.append('sections_std_entropy')
        names.append('text_section_entropy')
        names.append('data_section_entropy')
        names.append('code_ratio')
        names.append('data_ratio')
        names.append('suspicious_section_count')
        names.append('empty_section_count')
        names.append('writable_executable_sections')

        names.append('import_dll_count')
        names.append('import_api_count')
        names.append('import_suspicious_dll_count')
        names.append('import_suspicious_api_count')
        names.append('import_entropy')
        names.append('import_max_apis_per_dll')
        names.append('import_min_apis_per_dll')
        names.append('import_mean_apis_per_dll')
        names.append('import_std_apis_per_dll')
        names.append('has_kernel32')
        names.append('has_ntdll')
        names.append('has_ws2_32')
        names.append('has_wininet')
        names.append('has_urlmon')
        names.append('has_crypt32')

        names.append('export_count')
        names.append('has_exports')

        names.append('resource_count')
        names.append('resource_size')
        names.append('resource_entropy')
        names.append('has_manifest')
        names.append('has_version')
        names.append('has_icon')
        names.append('has_string_table')

        names.append('has_tls')
        names.append('has_relocations')
        names.append('has_debug')
        names.append('has_signature')

        names.append('string_count')
        names.append('suspicious_string_count')
        names.append('url_count')
        names.append('ip_count')
        names.append('path_count')
        names.append('registry_count')
        names.append('longest_string')

        names.append('entropy_0_1')
        names.append('entropy_1_2')
        names.append('entropy_2_3')
        names.append('entropy_3_4')
        names.append('entropy_4_5')
        names.append('entropy_5_6')
        names.append('entropy_6_7')
        names.append('entropy_7_8')

        names.append('byte_mean')
        names.append('byte_std')
        names.append('byte_min')
        names.append('byte_max')
        names.append('printable_ratio')
        names.append('zero_ratio')
        names.append('high_byte_ratio')

        return names

    def extract(self, file_path: str) -> Optional[np.ndarray]:
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 64 or file_size > self.max_file_size:
                return None

            with open(file_path, 'rb') as f:
                data = f.read(self.max_file_size)

            features = {}
            features['file_size'] = math.log10(file_size + 1)
            features['file_entropy'] = self._calculate_entropy(data)
            features['is_pe'] = self._is_pe(data)

            try:
                import lief
                pe = lief.parse(data)
                if pe is None or not isinstance(pe, lief.PE.Binary):
                    return self._build_default_features(file_size)

                self._extract_pe_header_features(pe, features)
                self._extract_section_features(pe, data, features)
                self._extract_import_features(pe, features)
                self._extract_export_features(pe, features)
                self._extract_resource_features(pe, features)
                self._extract_misc_features(pe, features)
                self._extract_string_features(data, features)
                self._extract_byte_distribution_features(data, features)
            except Exception:
                self._extract_string_features(data, features)
                self._extract_byte_distribution_features(data, features)
                self._fill_pe_defaults(features)

            return self._features_to_vector(features)

        except Exception:
            return None

    def _is_pe(self, data: bytes) -> int:
        if len(data) < 64:
            return 0
        if data[0:2] != b'MZ':
            return 0
        try:
            pe_offset = int.from_bytes(data[60:64], 'little')
            if pe_offset < 0 or pe_offset + 4 > len(data):
                return 0
            return 1 if data[pe_offset:pe_offset+4] == b'PE\x00\x00' else 0
        except Exception:
            return 0

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _extract_pe_header_features(self, pe, features: Dict[str, Any]):
        try:
            features['is_dll'] = 1 if pe.optional_header.is_dll else 0
            features['is_64bit'] = 1 if pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 0
        except Exception:
            features['is_dll'] = 0
            features['is_64bit'] = 0

        try:
            header = pe.header
            features['pe_offset'] = header.pe_offset if hasattr(header, 'pe_offset') else 0
            features['machine'] = header.machine.value if hasattr(header.machine, 'value') else int(header.machine)
            features['number_of_sections'] = header.numberof_sections
            features['timestamp'] = header.time_date_stamps
        except Exception:
            features['pe_offset'] = 0
            features['machine'] = 0
            features['number_of_sections'] = 0
            features['timestamp'] = 0

        try:
            optional = pe.optional_header
            features['subsystem'] = optional.subsystem.value if hasattr(optional.subsystem, 'value') else int(optional.subsystem)
            features['image_base'] = math.log10(optional.imagebase + 1)
            features['entry_point'] = math.log10(optional.addressof_entrypoint + 1)
            features['code_base'] = math.log10(optional.baseof_code + 1)
            features['section_alignment'] = math.log10(optional.section_alignment + 1)
            features['file_alignment'] = math.log10(optional.file_alignment + 1)
            features['size_of_image'] = math.log10(optional.sizeof_image + 1)
            features['size_of_headers'] = math.log10(optional.sizeof_headers + 1)
            features['checksum'] = optional.checksum
            features['dll_characteristics'] = optional.dll_characteristics
        except Exception:
            features['subsystem'] = 0
            features['image_base'] = 0
            features['entry_point'] = 0
            features['code_base'] = 0
            features['section_alignment'] = 0
            features['file_alignment'] = 0
            features['size_of_image'] = 0
            features['size_of_headers'] = 0
            features['checksum'] = 0
            features['dll_characteristics'] = 0

    def _extract_section_features(self, pe, data: bytes, features: Dict[str, Any]):
        sections = list(pe.sections) if pe.sections else []
        num_sections = min(len(sections), 10)

        entropies = []
        raw_sizes = []
        suspicious_count = 0
        empty_count = 0
        writable_executable_count = 0
        text_entropy = 0
        data_entropy = 0

        for i in range(10):
            if i < num_sections:
                sec = sections[i]
                name = sec.name.lower().strip('\x00') if sec.name else ''
                vsize = sec.virtual_size if sec.virtual_size else 0
                rsize = sec.size if sec.size else 0
                try:
                    sec_data = bytes(sec.content) if sec.content else b''
                except Exception:
                    sec_data = b''
                entropy = self._calculate_entropy(sec_data) if sec_data else 0.0

                try:
                    is_exec = 1 if sec.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE) else 0
                    is_write = 1 if sec.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE) else 0
                except Exception:
                    is_exec = 0
                    is_write = 0

                features[f'section_{i}_virtual_size'] = math.log10(vsize + 1)
                features[f'section_{i}_raw_size'] = math.log10(rsize + 1)
                features[f'section_{i}_entropy'] = entropy
                features[f'section_{i}_is_executable'] = is_exec
                features[f'section_{i}_is_writable'] = is_write
                features[f'section_{i}_name_hash'] = self._hash_string(name) / 2147483647.0

                entropies.append(entropy)
                raw_sizes.append(rsize)

                if is_exec and is_write:
                    writable_executable_count += 1
                if any(sus in name for sus in self.SUSPICIOUS_SECTIONS):
                    suspicious_count += 1
                if rsize == 0 or vsize == 0:
                    empty_count += 1
                if name in {'.text', 'code'}:
                    text_entropy = entropy
                if name in {'.data', '.rdata'}:
                    data_entropy = entropy
            else:
                for suffix in ['virtual_size', 'raw_size', 'entropy', 'is_executable', 'is_writable', 'name_hash']:
                    features[f'section_{i}_{suffix}'] = 0

        total_raw = sum(raw_sizes) if raw_sizes else 1
        code_ratio = sum(raw_sizes) / total_raw if raw_sizes else 0

        features['sections_max_entropy'] = max(entropies) if entropies else 0
        features['sections_min_entropy'] = min(entropies) if entropies else 0
        features['sections_mean_entropy'] = sum(entropies) / len(entropies) if entropies else 0
        features['sections_std_entropy'] = np.std(entropies) if entropies else 0
        features['text_section_entropy'] = text_entropy
        features['data_section_entropy'] = data_entropy
        features['code_ratio'] = code_ratio
        features['data_ratio'] = 0
        features['suspicious_section_count'] = suspicious_count
        features['empty_section_count'] = empty_count
        features['writable_executable_sections'] = writable_executable_count

    def _extract_import_features(self, pe, features: Dict[str, Any]):
        imports = pe.imports if pe.imports else []
        dll_names = []
        api_names = []
        suspicious_dll_count = 0
        suspicious_api_count = 0
        apis_per_dll = []

        for imp in imports:
            dll_name = imp.name.lower() if imp.name else ''
            dll_names.append(dll_name)
            if any(sus in dll_name for sus in self.SUSPICIOUS_DLLS):
                suspicious_dll_count += 1

            api_count = 0
            for entry in imp.entries:
                try:
                    api_name = entry.name.lower() if entry.name else ''
                except Exception:
                    api_name = ''
                api_names.append(api_name)
                api_count += 1
                if any(sus in api_name for sus in self.SUSPICIOUS_APIS):
                    suspicious_api_count += 1
            apis_per_dll.append(api_count)

        features['import_dll_count'] = len(dll_names)
        features['import_api_count'] = len(api_names)
        features['import_suspicious_dll_count'] = suspicious_dll_count
        features['import_suspicious_api_count'] = suspicious_api_count
        features['import_entropy'] = self._calculate_entropy(
            b''.join(api_name.encode() for api_name in api_names) if api_names else b''
        )

        if apis_per_dll:
            features['import_max_apis_per_dll'] = max(apis_per_dll)
            features['import_min_apis_per_dll'] = min(apis_per_dll)
            features['import_mean_apis_per_dll'] = sum(apis_per_dll) / len(apis_per_dll)
            features['import_std_apis_per_dll'] = np.std(apis_per_dll)
        else:
            features['import_max_apis_per_dll'] = 0
            features['import_min_apis_per_dll'] = 0
            features['import_mean_apis_per_dll'] = 0
            features['import_std_apis_per_dll'] = 0

        dll_set = set(dll_names)
        features['has_kernel32'] = 1 if any('kernel32' in d for d in dll_set) else 0
        features['has_ntdll'] = 1 if any('ntdll' in d for d in dll_set) else 0
        features['has_ws2_32'] = 1 if any('ws2_32' in d for d in dll_set) else 0
        features['has_wininet'] = 1 if any('wininet' in d for d in dll_set) else 0
        features['has_urlmon'] = 1 if any('urlmon' in d for d in dll_set) else 0
        features['has_crypt32'] = 1 if any('crypt32' in d for d in dll_set) else 0

    def _extract_export_features(self, pe, features: Dict[str, Any]):
        try:
            exports = pe.get_export()
            if exports and exports.entries:
                features['export_count'] = len(exports.entries)
                features['has_exports'] = 1
            else:
                features['export_count'] = 0
                features['has_exports'] = 0
        except Exception:
            features['export_count'] = 0
            features['has_exports'] = 0

    def _extract_resource_features(self, pe, features: Dict[str, Any]):
        try:
            resources = pe.resources
            if resources and hasattr(resources, 'childs'):
                childs = list(resources.childs)
                resource_count = len(childs)
                resource_size = 0
                resource_data = b''
                has_manifest = 0
                has_version = 0
                has_icon = 0
                has_string_table = 0

                for node in childs:
                    try:
                        if hasattr(node, 'content') and node.content:
                            content = bytes(node.content)
                            resource_size += len(content)
                            resource_data += content
                    except Exception:
                        pass

                    rtype = None
                    try:
                        if hasattr(node, 'id') and node.id in self.RT_TYPES:
                            rtype = self.RT_TYPES[node.id]
                    except Exception:
                        pass

                    if rtype == 'manifest':
                        has_manifest = 1
                    elif rtype == 'version':
                        has_version = 1
                    elif rtype in ('icon', 'group_icon'):
                        has_icon = 1
                    elif rtype == 'string':
                        has_string_table = 1

                features['resource_count'] = resource_count
                features['resource_size'] = math.log10(resource_size + 1)
                features['resource_entropy'] = self._calculate_entropy(resource_data) if resource_data else 0
                features['has_manifest'] = has_manifest
                features['has_version'] = has_version
                features['has_icon'] = has_icon
                features['has_string_table'] = has_string_table
            else:
                features['resource_count'] = 0
                features['resource_size'] = 0
                features['resource_entropy'] = 0
                features['has_manifest'] = 0
                features['has_version'] = 0
                features['has_icon'] = 0
                features['has_string_table'] = 0
        except Exception:
            features['resource_count'] = 0
            features['resource_size'] = 0
            features['resource_entropy'] = 0
            features['has_manifest'] = 0
            features['has_version'] = 0
            features['has_icon'] = 0
            features['has_string_table'] = 0

    def _extract_misc_features(self, pe, features: Dict[str, Any]):
        try:
            features['has_tls'] = 1 if pe.tls else 0
        except Exception:
            features['has_tls'] = 0

        try:
            features['has_relocations'] = 1 if pe.relocations else 0
        except Exception:
            features['has_relocations'] = 0

        try:
            features['has_debug'] = 1 if pe.debug else 0
        except Exception:
            features['has_debug'] = 0

        try:
            features['has_signature'] = 1 if pe.authenticode and pe.authenticode.has_signature else 0
        except Exception:
            features['has_signature'] = 0

    def _extract_string_features(self, data: bytes, features: Dict[str, Any]):
        strings = re.findall(rb'[\x20-\x7e]{4,}', data)
        decoded = [s.decode('ascii', errors='ignore') for s in strings]

        suspicious_patterns = {
            'url': re.compile(r'https?://[^\s\"<>]+', re.IGNORECASE),
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'path': re.compile(r'[a-zA-Z]:\\\\[^\s\"<>]+', re.IGNORECASE),
            'registry': re.compile(r'HKEY_[A-Z_]+', re.IGNORECASE),
        }

        suspicious_count = 0
        url_count = 0
        ip_count = 0
        path_count = 0
        registry_count = 0

        for s in decoded:
            lower = s.lower()
            if any(sus in lower for sus in self.SUSPICIOUS_APIS):
                suspicious_count += 1
            if suspicious_patterns['url'].search(s):
                url_count += 1
            if suspicious_patterns['ip'].search(s):
                ip_count += 1
            if suspicious_patterns['path'].search(s):
                path_count += 1
            if suspicious_patterns['registry'].search(s):
                registry_count += 1

        features['string_count'] = len(decoded)
        features['suspicious_string_count'] = suspicious_count
        features['url_count'] = url_count
        features['ip_count'] = ip_count
        features['path_count'] = path_count
        features['registry_count'] = registry_count
        features['longest_string'] = max(len(s) for s in decoded) if decoded else 0

    def _extract_byte_distribution_features(self, data: bytes, features: Dict[str, Any]):
        if not data:
            for key in ['byte_mean', 'byte_std', 'byte_min', 'byte_max', 'printable_ratio', 'zero_ratio', 'high_byte_ratio']:
                features[key] = 0
            for i in range(8):
                features[f'entropy_{i}_{i+1}'] = 0
            return

        arr = np.frombuffer(data, dtype=np.uint8)
        features['byte_mean'] = float(np.mean(arr))
        features['byte_std'] = float(np.std(arr))
        features['byte_min'] = float(np.min(arr))
        features['byte_max'] = float(np.max(arr))
        features['printable_ratio'] = float(np.sum((arr >= 32) & (arr <= 126))) / len(arr)
        features['zero_ratio'] = float(np.sum(arr == 0)) / len(arr)
        features['high_byte_ratio'] = float(np.sum(arr >= 128)) / len(arr)

        block_size = max(1, len(data) // 8)
        for i in range(8):
            start = i * block_size
            end = start + block_size if i < 7 else len(data)
            block = data[start:end]
            features[f'entropy_{i}_{i+1}'] = self._calculate_entropy(block)

    def _fill_pe_defaults(self, features: Dict[str, Any]):
        defaults = {
            'is_dll': 0, 'is_64bit': 0, 'pe_offset': 0, 'machine': 0,
            'subsystem': 0, 'timestamp': 0, 'image_base': 0, 'entry_point': 0,
            'code_base': 0, 'section_alignment': 0, 'file_alignment': 0,
            'size_of_image': 0, 'size_of_headers': 0, 'checksum': 0,
            'dll_characteristics': 0, 'number_of_sections': 0,
            'sections_max_entropy': 0, 'sections_min_entropy': 0,
            'sections_mean_entropy': 0, 'sections_std_entropy': 0,
            'text_section_entropy': 0, 'data_section_entropy': 0,
            'code_ratio': 0, 'data_ratio': 0, 'suspicious_section_count': 0,
            'empty_section_count': 0, 'writable_executable_sections': 0,
            'import_dll_count': 0, 'import_api_count': 0,
            'import_suspicious_dll_count': 0, 'import_suspicious_api_count': 0,
            'import_entropy': 0, 'import_max_apis_per_dll': 0,
            'import_min_apis_per_dll': 0, 'import_mean_apis_per_dll': 0,
            'import_std_apis_per_dll': 0, 'has_kernel32': 0, 'has_ntdll': 0,
            'has_ws2_32': 0, 'has_wininet': 0, 'has_urlmon': 0, 'has_crypt32': 0,
            'export_count': 0, 'has_exports': 0, 'resource_count': 0,
            'resource_size': 0, 'resource_entropy': 0, 'has_manifest': 0,
            'has_version': 0, 'has_icon': 0, 'has_string_table': 0,
            'has_tls': 0, 'has_relocations': 0, 'has_debug': 0, 'has_signature': 0
        }
        for i in range(10):
            defaults[f'section_{i}_virtual_size'] = 0
            defaults[f'section_{i}_raw_size'] = 0
            defaults[f'section_{i}_entropy'] = 0
            defaults[f'section_{i}_is_executable'] = 0
            defaults[f'section_{i}_is_writable'] = 0
            defaults[f'section_{i}_name_hash'] = 0
        for key, value in defaults.items():
            if key not in features:
                features[key] = value

    def _build_default_features(self, file_size: int) -> np.ndarray:
        features = {
            'file_size': math.log10(file_size + 1),
            'file_entropy': 0,
            'is_pe': 0,
        }
        self._fill_pe_defaults(features)
        self._extract_string_features(b'', features)
        self._extract_byte_distribution_features(b'', features)
        return self._features_to_vector(features)

    def _features_to_vector(self, features: Dict[str, Any]) -> np.ndarray:
        vector = []
        for name in self.feature_names:
            value = features.get(name, 0)
            vector.append(float(value))
        return np.array(vector, dtype=np.float32)

    @staticmethod
    def _hash_string(s: str) -> float:
        if not s:
            return 0.0
        h = hashlib.md5(s.encode()).hexdigest()[:8]
        return (int(h, 16) % 2147483647) / 2147483647.0


if __name__ == '__main__':
    extractor = PEFeatureExtractor()
    print(f'Feature count: {len(extractor.feature_names)}')
    import sys
    if len(sys.argv) > 1:
        features = extractor.extract(sys.argv[1])
        if features is not None:
            print(f'Extracted {len(features)} features')
            print(features[:20])
