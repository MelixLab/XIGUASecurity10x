; ============================================================
; XIGUASecurity NSIS Installer - MS Store 兼容返回值处理
; 提供标准的 Windows Installer 退出码
; ============================================================

; 标准 Windows Installer 错误码
!define ERROR_SUCCESS                  0
!define ERROR_INSTALL_USEREXIT         1602
!define ERROR_INSTALL_FAILURE          1603
!define ERROR_INSTALL_ALREADY_RUNNING  1618
!define ERROR_DISK_FULL                112
!define ERROR_SUCCESS_REBOOT_REQUIRED  3010

; ============================================================
; 安装前钩子：创建互斥体防止重复安装
; ============================================================
!macro NSIS_HOOK_PREINSTALL
  ; 检查是否已有安装实例在运行
  System::Call 'kernel32::CreateMutexW(i 0, i 0, w "XIGUASecurity_Installer_Mutex") i .r0'
  System::Call 'kernel32::GetLastError() i .r1'
  ${If} $1 = 183  ; ERROR_ALREADY_EXISTS
    SetErrorLevel ${ERROR_INSTALL_ALREADY_RUNNING}
    Abort "安装程序已存在，另一个安装正在进行中。"
  ${EndIf}
!macroend

; ============================================================
; 安装后钩子：设置成功返回值
; ============================================================
!macro NSIS_HOOK_POSTINSTALL
  ; 检查是否需要重启
  ${If} ${RebootFlag}
    SetErrorLevel ${ERROR_SUCCESS_REBOOT_REQUIRED}
  ${Else}
    SetErrorLevel ${ERROR_SUCCESS}
  ${EndIf}
!macroend

; ============================================================
; 卸载前钩子
; ============================================================
!macro NSIS_HOOK_PREUNINSTALL
  ; 无需特殊处理
!macroend

; ============================================================
; 卸载后钩子
; ============================================================
!macro NSIS_HOOK_POSTUNINSTALL
  SetErrorLevel ${ERROR_SUCCESS}
!macroend

; ============================================================
; 安装初始化：处理静默模式下的磁盘空间检查
; ============================================================
!macro NSIS_HOOK_CHECKSPACE
  ; 检查目标磁盘空间
  ${If} ${Silent}
    SectionGetSize "${INSTALL_SECTION}" $0
    ${If} $0 > $8  ; $8 是 NSIS 内部的目标磁盘可用空间
      SetErrorLevel ${ERROR_DISK_FULL}
      Abort "磁盘空间不足，无法完成安装。"
    ${EndIf}
  ${EndIf}
!macroend
