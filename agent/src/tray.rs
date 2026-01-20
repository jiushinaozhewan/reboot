//! System tray management for the agent

use native_dialog::{MessageDialog, MessageType};
use std::sync::mpsc;
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem},
    TrayIcon, TrayIconBuilder,
};
use tracing::{error, info, warn};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::Foundation::{HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
    Win32::Graphics::Gdi::UpdateWindow,
    Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    },
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GLOBAL_ALLOC_FLAGS},
    Win32::UI::Input::KeyboardAndMouse::SetFocus,
    Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        GetWindowTextLengthW, GetWindowTextW, MessageBoxW, PostQuitMessage, RegisterClassW,
        SetWindowTextW, ShowWindow, TranslateMessage, UnregisterClassW, CS_HREDRAW, CS_VREDRAW,
        CW_USEDEFAULT, ES_AUTOHSCROLL, HMENU, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION,
        MB_OK, MB_YESNO, MESSAGEBOX_RESULT, MSG, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE,
        WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD,
        WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    },
};

/// Menu actions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    SetPort,
    ShowKey,
    SetKey,
    ToggleAutoStart,
    Exit,
}

/// Result of a settings dialog
#[derive(Debug, Clone)]
pub enum SettingsResult {
    /// New port was set, restart required
    PortChanged(u16),
    /// New PSK was set, restart required
    KeyChanged(String),
    /// Auto-start setting changed
    AutoStartChanged(bool),
    /// No change
    Cancelled,
}

/// Tray application state
pub struct TrayApp {
    action_tx: mpsc::Sender<TrayAction>,
    _tray_icon: Option<TrayIcon>,
    port_item_id: tray_icon::menu::MenuId,
    key_item_id: tray_icon::menu::MenuId,
    set_key_item_id: tray_icon::menu::MenuId,
    autostart_item_id: tray_icon::menu::MenuId,
    exit_item_id: tray_icon::menu::MenuId,
    autostart_enabled: bool,
}

impl TrayApp {
    pub fn new(action_tx: mpsc::Sender<TrayAction>, autostart_enabled: bool) -> Self {
        Self {
            action_tx,
            _tray_icon: None,
            port_item_id: tray_icon::menu::MenuId::new("port"),
            key_item_id: tray_icon::menu::MenuId::new("key"),
            set_key_item_id: tray_icon::menu::MenuId::new("set_key"),
            autostart_item_id: tray_icon::menu::MenuId::new("autostart"),
            exit_item_id: tray_icon::menu::MenuId::new("exit"),
            autostart_enabled,
        }
    }

    fn create_tray_icon(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create menu
        let menu = Menu::new();

        let port_item = MenuItem::with_id(self.port_item_id.clone(), "端口设置", true, None);
        let key_item = MenuItem::with_id(self.key_item_id.clone(), "显示密钥", true, None);
        let set_key_item = MenuItem::with_id(self.set_key_item_id.clone(), "修改密钥", true, None);
        let separator1 = tray_icon::menu::PredefinedMenuItem::separator();
        let autostart_item = CheckMenuItem::with_id(
            self.autostart_item_id.clone(),
            "开机启动",
            true,
            self.autostart_enabled,
            None,
        );
        let separator2 = tray_icon::menu::PredefinedMenuItem::separator();
        let exit_item = MenuItem::with_id(self.exit_item_id.clone(), "退出", true, None);

        menu.append_items(&[
            &port_item,
            &key_item,
            &set_key_item,
            &separator1,
            &autostart_item,
            &separator2,
            &exit_item,
        ])?;

        // Create icon (using a simple embedded icon)
        let icon = create_default_icon();

        // Build tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("远程电源管理代理")
            .with_icon(icon)
            .build()?;

        self._tray_icon = Some(tray_icon);
        info!("Tray icon created");

        Ok(())
    }

    fn handle_menu_event(&self, event: MenuEvent) {
        let action = if event.id == self.port_item_id {
            Some(TrayAction::SetPort)
        } else if event.id == self.key_item_id {
            Some(TrayAction::ShowKey)
        } else if event.id == self.set_key_item_id {
            Some(TrayAction::SetKey)
        } else if event.id == self.autostart_item_id {
            Some(TrayAction::ToggleAutoStart)
        } else if event.id == self.exit_item_id {
            Some(TrayAction::Exit)
        } else {
            None
        };

        if let Some(action) = action {
            if let Err(e) = self.action_tx.send(action) {
                error!("Failed to send tray action: {}", e);
            }
        }
    }
}

impl ApplicationHandler for TrayApp {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        if self._tray_icon.is_none() {
            if let Err(e) = self.create_tray_icon() {
                error!("Failed to create tray icon: {}", e);
            }
        }
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
        // We don't have any windows
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // Process menu events
        if let Ok(event) = MenuEvent::receiver().try_recv() {
            self.handle_menu_event(event);
        }

        event_loop.set_control_flow(ControlFlow::Wait);
    }
}

/// Create a default icon (a simple colored square)
fn create_default_icon() -> tray_icon::Icon {
    // Create a simple 32x32 RGBA icon (blue square)
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);

    for y in 0..size {
        for x in 0..size {
            // Create a simple power icon shape
            let center_x = size / 2;
            let center_y = size / 2;
            let dx = (x as i32 - center_x as i32).abs() as u32;
            let dy = (y as i32 - center_y as i32).abs() as u32;
            let dist = ((dx * dx + dy * dy) as f32).sqrt();

            // Circle
            if dist < 12.0 && dist > 8.0 {
                // Green ring
                rgba.extend_from_slice(&[0x00, 0xCC, 0x00, 0xFF]);
            } else if x == center_x && y < center_y && dy < 10 {
                // Vertical line (power symbol)
                rgba.extend_from_slice(&[0x00, 0xCC, 0x00, 0xFF]);
            } else {
                // Transparent
                rgba.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            }
        }
    }

    tray_icon::Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

/// Run the tray event loop
pub fn run_tray(
    action_tx: mpsc::Sender<TrayAction>,
    autostart_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoop::new()?;
    let mut app = TrayApp::new(action_tx, autostart_enabled);

    event_loop.run_app(&mut app)?;

    Ok(())
}

/// Copy text to Windows clipboard
#[cfg(windows)]
fn copy_to_clipboard(text: &str) -> bool {
    use std::ptr;

    unsafe {
        // Open clipboard
        if OpenClipboard(HWND(ptr::null_mut())).is_err() {
            warn!("Failed to open clipboard");
            return false;
        }

        // Empty clipboard
        if EmptyClipboard().is_err() {
            warn!("Failed to empty clipboard");
            let _ = CloseClipboard();
            return false;
        }

        // Allocate global memory for the text (including null terminator)
        let text_bytes = text.as_bytes();
        let len = text_bytes.len() + 1;

        // GMEM_MOVEABLE = 0x0002
        let h_mem = match GlobalAlloc(GLOBAL_ALLOC_FLAGS(0x0002), len) {
            Ok(h) => h,
            Err(_) => {
                warn!("Failed to allocate global memory");
                let _ = CloseClipboard();
                return false;
            }
        };

        // Lock memory and copy text
        let ptr = GlobalLock(h_mem);
        if ptr.is_null() {
            warn!("Failed to lock global memory");
            let _ = CloseClipboard();
            return false;
        }

        ptr::copy_nonoverlapping(text_bytes.as_ptr(), ptr as *mut u8, text_bytes.len());
        // Add null terminator
        *((ptr as *mut u8).add(text_bytes.len())) = 0;

        let _ = GlobalUnlock(h_mem);

        // Set clipboard data (CF_TEXT = 1)
        if SetClipboardData(1, HANDLE(h_mem.0)).is_err() {
            warn!("Failed to set clipboard data");
            let _ = CloseClipboard();
            return false;
        }

        let _ = CloseClipboard();
        true
    }
}

#[cfg(not(windows))]
fn copy_to_clipboard(_text: &str) -> bool {
    false
}

// ============================================================================
// Windows Input Dialog Implementation
// ============================================================================

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Show an error message box (works in any thread)
#[cfg(windows)]
fn show_error_message(title: &str, message: &str) {
    unsafe {
        let title_wide = to_wide(title);
        let text_wide = to_wide(message);
        MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(text_wide.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
fn show_error_message(title: &str, message: &str) {
    let _ = MessageDialog::new()
        .set_title(title)
        .set_text(message)
        .set_type(MessageType::Error)
        .show_alert();
}

#[cfg(windows)]
static mut DIALOG_RESULT: Option<String> = None;
#[cfg(windows)]
static mut EDIT_HWND: HWND = HWND(std::ptr::null_mut());
#[cfg(windows)]
static mut LABEL_HWND: HWND = HWND(std::ptr::null_mut());
#[cfg(windows)]
static mut DIALOG_LABEL: Option<String> = None;

#[cfg(windows)]
const ID_EDIT: i32 = 101;
#[cfg(windows)]
const ID_OK: i32 = 102;
#[cfg(windows)]
const ID_CANCEL: i32 = 103;
#[cfg(windows)]
const ID_LABEL: i32 = 104;

#[cfg(windows)]
unsafe extern "system" fn dialog_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hinstance: HINSTANCE = GetModuleHandleW(PCWSTR::null())
                .ok()
                .map(|h| HINSTANCE(h.0))
                .unwrap_or_default();

            // Create label with stored text
            let label_class = to_wide("STATIC");
            let label_text = DIALOG_LABEL.as_deref().unwrap_or("请输入值:");
            let label_text_wide = to_wide(label_text);
            if let Ok(label) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(label_class.as_ptr()),
                PCWSTR(label_text_wide.as_ptr()),
                WS_CHILD | WS_VISIBLE,
                10,
                10,
                280,
                20,
                hwnd,
                HMENU(ID_LABEL as *mut _),
                hinstance,
                None,
            ) {
                LABEL_HWND = label;
            }

            // Create edit control
            let edit_class = to_wide("EDIT");
            if let Ok(edit) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(edit_class.as_ptr()),
                PCWSTR::null(),
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
                10,
                35,
                280,
                25,
                hwnd,
                HMENU(ID_EDIT as *mut _),
                hinstance,
                None,
            ) {
                EDIT_HWND = edit;
            }

            // Create OK button
            let button_class = to_wide("BUTTON");
            let ok_text = to_wide("确定");
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(button_class.as_ptr()),
                PCWSTR(ok_text.as_ptr()),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                60,
                70,
                80,
                28,
                hwnd,
                HMENU(ID_OK as *mut _),
                hinstance,
                None,
            );

            // Create Cancel button
            let cancel_text = to_wide("取消");
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(button_class.as_ptr()),
                PCWSTR(cancel_text.as_ptr()),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                160,
                70,
                80,
                28,
                hwnd,
                HMENU(ID_CANCEL as *mut _),
                hinstance,
                None,
            );

            // Set focus to edit control
            if !EDIT_HWND.0.is_null() {
                let _ = SetFocus(EDIT_HWND);
            }

            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            if id == ID_OK {
                // Get text from edit control
                let len = GetWindowTextLengthW(EDIT_HWND) as usize;
                if len > 0 {
                    let mut buffer: Vec<u16> = vec![0; len + 1];
                    GetWindowTextW(EDIT_HWND, &mut buffer);
                    let text = String::from_utf16_lossy(&buffer[..len]);
                    DIALOG_RESULT = Some(text);
                } else {
                    DIALOG_RESULT = Some(String::new());
                }
                PostQuitMessage(0);
            } else if id == ID_CANCEL {
                DIALOG_RESULT = None;
                PostQuitMessage(0);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            DIALOG_RESULT = None;
            PostQuitMessage(0);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Show an input dialog and return the user input
#[cfg(windows)]
pub fn show_input_dialog(title: &str, label: &str, default_value: &str) -> Option<String> {
    use std::ptr;

    unsafe {
        DIALOG_RESULT = None;
        EDIT_HWND = HWND(ptr::null_mut());
        LABEL_HWND = HWND(ptr::null_mut());
        DIALOG_LABEL = Some(label.to_string());

        let hinstance: HINSTANCE = GetModuleHandleW(PCWSTR::null())
            .ok()
            .map(|h| HINSTANCE(h.0))
            .unwrap_or_default();
        let class_name = to_wide("RebootAgentInputDialog");
        let title_wide = to_wide(title);

        // Register window class
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(dialog_proc),
            hInstance: hinstance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };

        let _ = RegisterClassW(&wc);

        // Create window
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title_wide.as_ptr()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            320,
            145,
            HWND(ptr::null_mut()),
            None,
            hinstance,
            None,
        );

        let hwnd = match hwnd {
            Ok(h) => h,
            Err(_) => {
                error!("Failed to create dialog window");
                DIALOG_LABEL = None;
                return None;
            }
        };

        if hwnd.0.is_null() {
            error!("Failed to create dialog window");
            DIALOG_LABEL = None;
            return None;
        }

        // Set default value to edit control
        if !EDIT_HWND.0.is_null() {
            let default_wide = to_wide(default_value);
            let _ = SetWindowTextW(EDIT_HWND, PCWSTR(default_wide.as_ptr()));
        }

        // Show window
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);

        // Message loop
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND(ptr::null_mut()), 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Cleanup
        let _ = DestroyWindow(hwnd);
        let _ = UnregisterClassW(PCWSTR(class_name.as_ptr()), hinstance);
        DIALOG_LABEL = None;

        DIALOG_RESULT.take()
    }
}

#[cfg(not(windows))]
pub fn show_input_dialog(_title: &str, _label: &str, _default_value: &str) -> Option<String> {
    None
}

// ============================================================================
// Dialog Functions
// ============================================================================

/// Show a dialog to get the new port
pub fn show_port_dialog(current_port: u16) -> Option<u16> {
    let result = show_input_dialog(
        "端口设置",
        &format!("请输入新端口号 (当前: {}):", current_port),
        &current_port.to_string(),
    );

    if let Some(input) = result {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }
        match trimmed.parse::<u16>() {
            Ok(port) if port > 0 => {
                if port != current_port {
                    Some(port)
                } else {
                    // Same port, no change
                    None
                }
            }
            Ok(_) => {
                show_error_message("错误", "端口号必须大于 0");
                None
            }
            Err(_) => {
                show_error_message("错误", "请输入有效的端口号 (1-65535)");
                None
            }
        }
    } else {
        None
    }
}

/// Show a dialog to set a new PSK key
pub fn show_set_key_dialog(current_key: &str) -> Option<String> {
    let result = show_input_dialog(
        "修改密钥",
        "请输入新的 64 位十六进制密钥:",
        current_key,
    );

    if let Some(input) = result {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Validate hex format and length
        if trimmed.len() != 64 {
            show_error_message(
                "错误",
                &format!(
                    "密钥长度必须为 64 个十六进制字符\n当前长度: {}",
                    trimmed.len()
                ),
            );
            return None;
        }

        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            show_error_message("错误", "密钥只能包含十六进制字符 (0-9, a-f, A-F)");
            return None;
        }

        if trimmed == current_key {
            // Same key, no change
            return None;
        }

        Some(trimmed.to_lowercase())
    } else {
        None
    }
}

/// Show the PSK key and copy to clipboard
pub fn show_key_dialog(psk_hex: &str) {
    // Copy to clipboard first
    let copied = copy_to_clipboard(psk_hex);
    let copy_status = if copied {
        "✓ 密钥已复制到剪贴板"
    } else {
        "✗ 复制到剪贴板失败，请手动记录"
    };

    let message = format!(
        "{}\n\n{}\n\n请将密钥粘贴到控制端",
        copy_status, psk_hex
    );

    #[cfg(windows)]
    unsafe {
        let title = to_wide("认证密钥");
        let text = to_wide(&message);
        MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    #[cfg(not(windows))]
    {
        let _ = MessageDialog::new()
            .set_title("认证密钥")
            .set_text(&message)
            .set_type(MessageType::Info)
            .show_alert();
    }
}

/// Show first-run welcome dialog and copy key to clipboard
pub fn show_welcome_dialog(psk_hex: &str, port: u16) {
    // Copy to clipboard first
    let copied = copy_to_clipboard(psk_hex);
    let copy_status = if copied {
        "✓ 密钥已复制到剪贴板"
    } else {
        "✗ 复制到剪贴板失败，请手动记录"
    };

    let message = format!(
        "服务已启动！\n\n监听端口: {}\n\n{}\n\n认证密钥:\n{}\n\n请将密钥粘贴到控制端，妥善保管！",
        port, copy_status, psk_hex
    );

    #[cfg(windows)]
    unsafe {
        let title = to_wide("远程电源管理代理 - 首次运行");
        let text = to_wide(&message);
        MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    #[cfg(not(windows))]
    {
        let _ = MessageDialog::new()
            .set_title("远程电源管理代理 - 首次运行")
            .set_text(&message)
            .set_type(MessageType::Info)
            .show_alert();
    }
}

/// Show restart confirmation dialog
pub fn show_restart_confirm_dialog(message: &str) -> bool {
    let full_message = format!("{}\n\n是否立即重启应用程序？", message);

    #[cfg(windows)]
    unsafe {
        let title = to_wide("需要重启");
        let text = to_wide(&full_message);
        let result = MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONQUESTION,
        );
        result == MESSAGEBOX_RESULT(6) // IDYES = 6
    }

    #[cfg(not(windows))]
    {
        let result = MessageDialog::new()
            .set_title("需要重启")
            .set_text(&full_message)
            .set_type(MessageType::Info)
            .show_confirm();

        match result {
            Ok(confirmed) => confirmed,
            Err(e) => {
                error!("Failed to show dialog: {}", e);
                false
            }
        }
    }
}

// ============================================================================
// Auto-start Management (Windows Registry)
// ============================================================================

#[cfg(windows)]
const AUTOSTART_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const AUTOSTART_VALUE_NAME: &str = "RebootAgent";

/// Check if auto-start is enabled
#[cfg(windows)]
pub fn is_autostart_enabled() -> bool {
    use windows::Win32::System::Registry::*;

    unsafe {
        let key_path = to_wide(AUTOSTART_REG_KEY);
        let mut hkey = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result.is_err() {
            return false;
        }

        let value_name = to_wide(AUTOSTART_VALUE_NAME);
        let exists = RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            None,
            None,
            None,
        )
        .is_ok();

        let _ = RegCloseKey(hkey);
        exists
    }
}

#[cfg(not(windows))]
pub fn is_autostart_enabled() -> bool {
    false
}

/// Set auto-start enabled/disabled
#[cfg(windows)]
pub fn set_autostart_enabled(enabled: bool) -> Result<(), String> {
    use windows::Win32::System::Registry::*;

    unsafe {
        let key_path = to_wide(AUTOSTART_REG_KEY);
        let mut hkey = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        );

        if result.is_err() {
            return Err(format!("无法打开注册表: {:?}", result));
        }

        let value_name = to_wide(AUTOSTART_VALUE_NAME);

        let final_result = if enabled {
            // Get current executable path
            let exe_path = std::env::current_exe()
                .map_err(|e| format!("无法获取程序路径: {}", e))?;
            let exe_path_str = exe_path.to_string_lossy();
            let exe_path_wide = to_wide(&exe_path_str);

            let byte_len = (exe_path_wide.len() * 2) as u32;
            RegSetValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    exe_path_wide.as_ptr() as *const u8,
                    byte_len as usize,
                )),
            )
        } else {
            RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()))
        };

        let _ = RegCloseKey(hkey);

        if final_result.is_ok() {
            info!("Auto-start {}", if enabled { "enabled" } else { "disabled" });
            Ok(())
        } else {
            Err(format!("注册表操作失败: {:?}", final_result))
        }
    }
}

#[cfg(not(windows))]
pub fn set_autostart_enabled(_enabled: bool) -> Result<(), String> {
    Err("开机启动仅支持 Windows 平台".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_icon() {
        let icon = create_default_icon();
        // Just check it doesn't panic
        drop(icon);
    }
}
