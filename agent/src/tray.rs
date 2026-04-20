//! System tray management for the agent

#[cfg(not(windows))]
use native_dialog::{MessageDialog, MessageType};
use std::sync::mpsc;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::sync::{Mutex, OnceLock};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::{Duration, Instant};
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
        SetForegroundWindow, SetWindowTextW, ShowWindow, TranslateMessage, UnregisterClassW,
        CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, ES_AUTOHSCROLL, HMENU, MB_ICONERROR,
        MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MESSAGEBOX_RESULT, MSG, SW_SHOW,
        WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WNDCLASSW,
        WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP,
        WS_VISIBLE,
    },
};

/// Menu actions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    SetPort,
    ShowKey,
    SetKey,
    ToggleAutoStart,
    ToggleLogging,
    Exit,
}

/// Tray application state
pub struct TrayApp {
    action_tx: mpsc::Sender<TrayAction>,
    _tray_icon: Option<TrayIcon>,
    port_item_id: tray_icon::menu::MenuId,
    key_item_id: tray_icon::menu::MenuId,
    set_key_item_id: tray_icon::menu::MenuId,
    autostart_item_id: tray_icon::menu::MenuId,
    log_item_id: tray_icon::menu::MenuId,
    exit_item_id: tray_icon::menu::MenuId,
    autostart_enabled: bool,
    log_enabled: bool,
    next_tray_retry_at: Instant,
}

impl TrayApp {
    pub fn new(
        action_tx: mpsc::Sender<TrayAction>,
        autostart_enabled: bool,
        log_enabled: bool,
    ) -> Self {
        Self {
            action_tx,
            _tray_icon: None,
            port_item_id: tray_icon::menu::MenuId::new("port"),
            key_item_id: tray_icon::menu::MenuId::new("key"),
            set_key_item_id: tray_icon::menu::MenuId::new("set_key"),
            autostart_item_id: tray_icon::menu::MenuId::new("autostart"),
            log_item_id: tray_icon::menu::MenuId::new("logging"),
            exit_item_id: tray_icon::menu::MenuId::new("exit"),
            autostart_enabled,
            log_enabled,
            next_tray_retry_at: Instant::now(),
        }
    }

    fn ensure_tray_icon(&mut self) {
        if self._tray_icon.is_some() {
            return;
        }

        info!("Attempting to initialize tray icon");
        match self.create_tray_icon() {
            Ok(()) => {
                info!("Tray icon initialized");
            }
            Err(e) => {
                self.next_tray_retry_at = Instant::now() + Duration::from_secs(2);
                error!("Failed to create tray icon, will retry: {}", e);
            }
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
        let log_item = CheckMenuItem::with_id(
            self.log_item_id.clone(),
            "调试日志",
            true,
            self.log_enabled,
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
            &log_item,
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
        info!(
            "Tray icon created with menu ids: port={:?}, key={:?}, set_key={:?}, autostart={:?}, logging={:?}, exit={:?}",
            self.port_item_id,
            self.key_item_id,
            self.set_key_item_id,
            self.autostart_item_id,
            self.log_item_id,
            self.exit_item_id
        );

        Ok(())
    }

    fn handle_menu_event(&self, event: MenuEvent) {
        info!("Tray menu event received: id={:?}", event.id);
        let action = if event.id == self.port_item_id {
            Some(TrayAction::SetPort)
        } else if event.id == self.key_item_id {
            Some(TrayAction::ShowKey)
        } else if event.id == self.set_key_item_id {
            Some(TrayAction::SetKey)
        } else if event.id == self.autostart_item_id {
            Some(TrayAction::ToggleAutoStart)
        } else if event.id == self.log_item_id {
            Some(TrayAction::ToggleLogging)
        } else if event.id == self.exit_item_id {
            Some(TrayAction::Exit)
        } else {
            None
        };

        if let Some(action) = action {
            info!("Tray menu event mapped to action: {:?}", action);
            if let Err(e) = self.action_tx.send(action) {
                error!("Failed to send tray action: {}", e);
            } else {
                info!("Tray action sent to worker thread successfully");
            }
        } else {
            warn!("Tray menu event did not match any known action: id={:?}", event.id);
        }
    }
}

impl ApplicationHandler for TrayApp {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        self.ensure_tray_icon();
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

        if self._tray_icon.is_none() && Instant::now() >= self.next_tray_retry_at {
            self.ensure_tray_icon();
        }

        if self._tray_icon.is_none() {
            event_loop.set_control_flow(ControlFlow::WaitUntil(self.next_tray_retry_at));
        } else {
            event_loop.set_control_flow(ControlFlow::Wait);
        }
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
            let dx = (x as i32 - center_x as i32).unsigned_abs();
            let dy = (y as i32 - center_y as i32).unsigned_abs();
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
    log_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "Starting tray event loop, autostart_enabled={}, log_enabled={}",
        autostart_enabled,
        log_enabled
    );
    let event_loop = EventLoop::new()?;
    let mut app = TrayApp::new(action_tx, autostart_enabled, log_enabled);

    event_loop.run_app(&mut app)?;

    info!("Tray event loop exited");
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
#[derive(Default)]
struct DialogState {
    result: Option<String>,
    edit_hwnd: isize,
    label: Option<String>,
}

#[cfg(windows)]
fn dialog_state() -> &'static Mutex<DialogState> {
    static STATE: OnceLock<Mutex<DialogState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(DialogState::default()))
}

#[cfg(windows)]
fn hwnd_from_raw(raw: isize) -> HWND {
    HWND(raw as *mut _)
}

#[cfg(windows)]
const ID_EDIT: i32 = 101;
#[cfg(windows)]
const ID_OK: i32 = 102;
#[cfg(windows)]
const ID_CANCEL: i32 = 103;
#[cfg(windows)]
const ID_LABEL: i32 = 104;
#[cfg(windows)]
const DIALOG_HELPER_FLAG: &str = "--dialog-helper";
#[cfg(windows)]
const DIALOG_TITLE_HEX_ARG: &str = "--title-hex";
#[cfg(windows)]
const DIALOG_LABEL_HEX_ARG: &str = "--label-hex";
#[cfg(windows)]
const DIALOG_DEFAULT_HEX_ARG: &str = "--default-hex";
#[cfg(windows)]
const DIALOG_OUTPUT_ARG: &str = "--output";

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

            let label_class = to_wide("STATIC");
            let label_text = dialog_state()
                .lock()
                .unwrap()
                .label
                .clone()
                .unwrap_or_else(|| "请输入值:".to_string());
            let label_text_wide = to_wide(&label_text);
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(label_class.as_ptr()),
                PCWSTR(label_text_wide.as_ptr()),
                WS_CHILD | WS_VISIBLE,
                10,
                10,
                320,
                20,
                hwnd,
                HMENU(ID_LABEL as *mut _),
                hinstance,
                None,
            );

            let edit_class = to_wide("EDIT");
            if let Ok(edit) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(edit_class.as_ptr()),
                PCWSTR::null(),
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
                10,
                35,
                320,
                25,
                hwnd,
                HMENU(ID_EDIT as *mut _),
                hinstance,
                None,
            ) {
                dialog_state().lock().unwrap().edit_hwnd = edit.0 as isize;
            }

            let button_class = to_wide("BUTTON");
            let ok_text = to_wide("确定");
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(button_class.as_ptr()),
                PCWSTR(ok_text.as_ptr()),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                160,
                72,
                80,
                28,
                hwnd,
                HMENU(ID_OK as *mut _),
                hinstance,
                None,
            );

            let cancel_text = to_wide("取消");
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(button_class.as_ptr()),
                PCWSTR(cancel_text.as_ptr()),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                250,
                72,
                80,
                28,
                hwnd,
                HMENU(ID_CANCEL as *mut _),
                hinstance,
                None,
            );

            let edit_hwnd = hwnd_from_raw(dialog_state().lock().unwrap().edit_hwnd);
            if !edit_hwnd.0.is_null() {
                let _ = SetFocus(edit_hwnd);
            }

            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            if id == ID_OK {
                let edit_hwnd = hwnd_from_raw(dialog_state().lock().unwrap().edit_hwnd);
                let len = GetWindowTextLengthW(edit_hwnd) as usize;
                if len > 0 {
                    let mut buffer: Vec<u16> = vec![0; len + 1];
                    GetWindowTextW(edit_hwnd, &mut buffer);
                    let text = String::from_utf16_lossy(&buffer[..len]);
                    dialog_state().lock().unwrap().result = Some(text);
                } else {
                    dialog_state().lock().unwrap().result = Some(String::new());
                }
                let _ = DestroyWindow(hwnd);
            } else if id == ID_CANCEL {
                dialog_state().lock().unwrap().result = None;
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            dialog_state().lock().unwrap().result = None;
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
fn decode_hex_arg(name: &str, value: &str) -> Result<String, String> {
    let bytes = hex::decode(value).map_err(|e| format!("参数 {} 解析失败: {}", name, e))?;
    String::from_utf8(bytes).map_err(|e| format!("参数 {} 不是有效 UTF-8: {}", name, e))
}

#[cfg(windows)]
unsafe fn show_input_dialog_native(
    title: &str,
    label: &str,
    default_value: &str,
) -> Result<Option<String>, String> {
    {
        let mut state = dialog_state().lock().unwrap();
        state.result = None;
        state.edit_hwnd = 0;
        state.label = Some(label.to_string());
    }

    let hinstance: HINSTANCE = GetModuleHandleW(PCWSTR::null())
        .ok()
        .map(|h| HINSTANCE(h.0))
        .unwrap_or_default();
    let class_name = to_wide("RebootAgentDialogHelper");
    let title_wide = to_wide(title);

    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(dialog_proc),
        hInstance: hinstance,
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    let _ = RegisterClassW(&wc);

    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(WS_EX_TOPMOST.0),
        PCWSTR(class_name.as_ptr()),
        PCWSTR(title_wide.as_ptr()),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        360,
        150,
        HWND(std::ptr::null_mut()),
        None,
        hinstance,
        None,
    )
    .map_err(|e| format!("无法创建输入窗口: {}", e))?;

    if hwnd.0.is_null() {
        return Err("无法创建输入窗口".to_string());
    }

    let edit_hwnd = hwnd_from_raw(dialog_state().lock().unwrap().edit_hwnd);
    if !edit_hwnd.0.is_null() {
        let default_wide = to_wide(default_value);
        let _ = SetWindowTextW(edit_hwnd, PCWSTR(default_wide.as_ptr()));
    }

    let _ = ShowWindow(hwnd, SW_SHOW);
    let _ = UpdateWindow(hwnd);
    let _ = SetForegroundWindow(hwnd);

    let mut msg = MSG::default();
    while GetMessageW(&mut msg, HWND(std::ptr::null_mut()), 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    let _ = UnregisterClassW(PCWSTR(class_name.as_ptr()), hinstance);
    let mut state = dialog_state().lock().unwrap();
    state.label = None;
    state.edit_hwnd = 0;
    Ok(state.result.take())
}

#[cfg(windows)]
pub fn run_dialog_helper_if_requested() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some(DIALOG_HELPER_FLAG) {
        return None;
    }

    let mut title_hex = None;
    let mut label_hex = None;
    let mut default_hex = None;
    let mut output_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            DIALOG_TITLE_HEX_ARG => title_hex = args.next(),
            DIALOG_LABEL_HEX_ARG => label_hex = args.next(),
            DIALOG_DEFAULT_HEX_ARG => default_hex = args.next(),
            DIALOG_OUTPUT_ARG => output_path = args.next(),
            _ => {}
        }
    }

    let title = match title_hex
        .as_deref()
        .ok_or_else(|| "缺少标题参数".to_string())
        .and_then(|value| decode_hex_arg(DIALOG_TITLE_HEX_ARG, value))
    {
        Ok(value) => value,
        Err(_) => return Some(1),
    };
    let label = match label_hex
        .as_deref()
        .ok_or_else(|| "缺少标签参数".to_string())
        .and_then(|value| decode_hex_arg(DIALOG_LABEL_HEX_ARG, value))
    {
        Ok(value) => value,
        Err(_) => return Some(1),
    };
    let default_value = match default_hex
        .as_deref()
        .ok_or_else(|| "缺少默认值参数".to_string())
        .and_then(|value| decode_hex_arg(DIALOG_DEFAULT_HEX_ARG, value))
    {
        Ok(value) => value,
        Err(_) => return Some(1),
    };
    let output_path = match output_path {
        Some(value) => std::path::PathBuf::from(value),
        None => return Some(1),
    };

    match unsafe { show_input_dialog_native(&title, &label, &default_value) } {
        Ok(Some(value)) => {
            if std::fs::write(&output_path, value).is_ok() {
                Some(0)
            } else {
                Some(1)
            }
        }
        Ok(None) => Some(2),
        Err(_) => Some(1),
    }
}

/// Show an input dialog and return the user input
#[cfg(windows)]
pub fn show_input_dialog(title: &str, label: &str, default_value: &str) -> Option<String> {
    info!(
        "show_input_dialog entered via helper process: title={}, label={}, default_len={}",
        title,
        label,
        default_value.len()
    );

    let output_path = std::env::temp_dir().join(format!(
        "reboot-agent-dialog-{}-{}.txt",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0)
    ));
    let title_hex = hex::encode(title.as_bytes());
    let label_hex = hex::encode(label.as_bytes());
    let default_hex = hex::encode(default_value.as_bytes());
    let output_path_string = output_path.to_string_lossy().to_string();

    match std::env::current_exe() {
        Ok(exe_path) => match Command::new(exe_path)
            .args([
                DIALOG_HELPER_FLAG,
                DIALOG_TITLE_HEX_ARG,
                &title_hex,
                DIALOG_LABEL_HEX_ARG,
                &label_hex,
                DIALOG_DEFAULT_HEX_ARG,
                &default_hex,
                DIALOG_OUTPUT_ARG,
                &output_path_string,
            ])
            .status()
        {
            Ok(status) if status.code() == Some(0) => {
                let result = match std::fs::read_to_string(&output_path) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        error!("Failed to read helper dialog result: {}", e);
                        None
                    }
                };
                let _ = std::fs::remove_file(&output_path);
                info!(
                    "show_input_dialog returning via helper process: title={}, has_result={}, result_len={}",
                    title,
                    result.is_some(),
                    result.as_ref().map(|s| s.len()).unwrap_or(0)
                );
                result
            }
            Ok(status) if status.code() == Some(2) => {
                let _ = std::fs::remove_file(&output_path);
                info!(
                    "show_input_dialog returning via helper process: title={}, has_result=false, result_len=0",
                    title
                );
                None
            }
            Ok(status) => {
                let _ = std::fs::remove_file(&output_path);
                let code = status.code().unwrap_or(-1);
                error!(
                    "show_input_dialog helper exited abnormally: title={}, code={}",
                    title, code
                );
                show_error_message("错误", &format!("输入对话框异常退出，代码={}", code));
                None
            }
            Err(e) => {
                let _ = std::fs::remove_file(&output_path);
                error!("show_input_dialog failed to launch helper for title={}: {}", title, e);
                show_error_message("错误", &format!("无法启动输入对话框: {}", e));
                None
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&output_path);
            error!("show_input_dialog failed to resolve current executable: {}", e);
            show_error_message("错误", &format!("无法获取程序路径: {}", e));
            None
        }
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
    info!("show_port_dialog entered: current_port={}", current_port);
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
                    info!("show_port_dialog returning new port: {}", port);
                    Some(port)
                } else {
                    // Same port, no change
                    info!("show_port_dialog received unchanged port");
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
        info!("show_port_dialog cancelled or returned no input");
        None
    }
}

/// Show a dialog to set a new PSK key
pub fn show_set_key_dialog(current_key: &str) -> Option<String> {
    info!(
        "show_set_key_dialog entered: current_key_len={}",
        current_key.len()
    );
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
            info!("show_set_key_dialog received unchanged key");
            return None;
        }

        info!("show_set_key_dialog returning new key, len={}", trimmed.len());
        Some(trimmed.to_lowercase())
    } else {
        info!("show_set_key_dialog cancelled or returned no input");
        None
    }
}

/// Show the PSK key and copy to clipboard
pub fn show_key_dialog(psk_hex: &str) {
    info!("show_key_dialog entered: key_len={}", psk_hex.len());
    // Copy to clipboard first
    let copied = copy_to_clipboard(psk_hex);
    info!("show_key_dialog clipboard copy result: {}", copied);
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
    info!("show_key_dialog completed");
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
        let confirmed = result == MESSAGEBOX_RESULT(6);
        info!("show_restart_confirm_dialog result: {}", confirmed);
        confirmed // IDYES = 6
    }

    #[cfg(not(windows))]
    {
        let result = MessageDialog::new()
            .set_title("需要重启")
            .set_text(&full_message)
            .set_type(MessageType::Info)
            .show_confirm();

        match result {
            Ok(confirmed) => {
                info!("show_restart_confirm_dialog result: {}", confirmed);
                confirmed
            }
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
#[cfg(windows)]
const AUTOSTART_SCRIPT_NAME: &str = "RebootAgent.vbs";

#[cfg(windows)]
fn startup_folder_path() -> Result<std::path::PathBuf, String> {
    let app_data = dirs::data_dir().ok_or_else(|| "无法获取 AppData 路径".to_string())?;
    Ok(app_data
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup"))
}

#[cfg(windows)]
fn autostart_script_path() -> Result<std::path::PathBuf, String> {
    Ok(startup_folder_path()?.join(AUTOSTART_SCRIPT_NAME))
}

#[cfg(windows)]
fn has_autostart_script() -> Result<bool, String> {
    Ok(autostart_script_path()?.exists())
}

#[cfg(windows)]
fn build_autostart_script(exe_path: &std::path::Path) -> String {
    let exe_path = exe_path.to_string_lossy().replace('"', "\"\"");
    format!(
        "Set WshShell = CreateObject(\"WScript.Shell\")\r\nWshShell.Run \"\"\"{}\"\"\", 0, False\r\n",
        exe_path
    )
}

#[cfg(windows)]
fn remove_legacy_autostart_registry_value() -> Result<(), String> {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::*;

    unsafe {
        let key_path = to_wide(AUTOSTART_REG_KEY);
        let mut hkey = HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );

        if result.is_err() {
            return Ok(());
        }

        let value_name = to_wide(AUTOSTART_VALUE_NAME);
        let delete_result = RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()));
        let _ = RegCloseKey(hkey);

        if delete_result == ERROR_SUCCESS || delete_result == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(format!("清理旧注册表自启动失败: {:?}", delete_result))
        }
    }
}

#[cfg(windows)]
fn has_legacy_autostart_registry_value() -> bool {
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

#[cfg(windows)]
fn write_autostart_script_for_current_exe() -> Result<(), String> {
    let script_path = autostart_script_path()?;
    let exe_path = std::env::current_exe().map_err(|e| format!("无法获取程序路径: {}", e))?;
    let script = build_autostart_script(&exe_path);

    if let Some(parent) = script_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("无法创建启动目录: {}", e))?;
    }

    std::fs::write(&script_path, script).map_err(|e| format!("无法写入启动脚本: {}", e))?;
    Ok(())
}

#[cfg(windows)]
pub fn migrate_legacy_autostart() -> Result<bool, String> {
    if has_legacy_autostart_registry_value() && !has_autostart_script()? {
        write_autostart_script_for_current_exe()?;
        remove_legacy_autostart_registry_value()?;
        info!("Migrated auto-start from registry Run to startup folder script");
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(not(windows))]
pub fn migrate_legacy_autostart() -> Result<bool, String> {
    Ok(false)
}

/// Check if auto-start is enabled
#[cfg(windows)]
pub fn is_autostart_enabled() -> bool {
    has_autostart_script().unwrap_or(false) || has_legacy_autostart_registry_value()
}

#[cfg(not(windows))]
pub fn is_autostart_enabled() -> bool {
    false
}

/// Set auto-start enabled/disabled
#[cfg(windows)]
pub fn set_autostart_enabled(enabled: bool) -> Result<(), String> {
    if enabled {
        write_autostart_script_for_current_exe()?;
        remove_legacy_autostart_registry_value()?;
    } else {
        let script_path = autostart_script_path()?;
        if script_path.exists() {
            std::fs::remove_file(&script_path)
                .map_err(|e| format!("无法删除启动脚本: {}", e))?;
        }
        remove_legacy_autostart_registry_value()?;
    }

    info!(
        "Auto-start {} via startup folder script",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
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

    #[cfg(windows)]
    #[test]
    fn test_build_autostart_script_quotes_exe_path() {
        let script = build_autostart_script(std::path::Path::new(
            r#"D:\Program Files\Reboot Agent\reboot-agent.exe"#,
        ));
        assert!(script.contains(r#""""D:\Program Files\Reboot Agent\reboot-agent.exe""""#));
        assert!(script.contains("WshShell.Run"));
    }
}
