//! Command executor for Windows system operations

use common::{Command, ExecutionError};
use tracing::{error, info};

#[cfg(windows)]
use std::io;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ACCESS_DENIED, ERROR_NOT_ALL_ASSIGNED,
    ERROR_NO_SHUTDOWN_IN_PROGRESS, ERROR_SUCCESS, HANDLE, WIN32_ERROR,
};
#[cfg(windows)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
#[cfg(windows)]
use windows::Win32::System::Shutdown::{
    AbortSystemShutdownW, InitiateShutdownW, SHUTDOWN_FORCE_OTHERS, SHUTDOWN_FORCE_SELF,
    SHUTDOWN_POWEROFF, SHUTDOWN_RESTART, SHTDN_REASON_FLAG_PLANNED,
    SHTDN_REASON_MAJOR_APPLICATION, SHTDN_REASON_MINOR_MAINTENANCE,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Execute a power command on Windows
pub async fn execute_command(cmd: &Command) -> Result<(), ExecutionError> {
    match cmd {
        Command::Shutdown { force, delay_sec } => {
            info!("Executing shutdown (force={}, delay={}s)", force, delay_sec);
            execute_shutdown(false, *force, *delay_sec)
        }
        Command::Restart { force, delay_sec } => {
            info!("Executing restart (force={}, delay={}s)", force, delay_sec);
            execute_shutdown(true, *force, *delay_sec)
        }
        Command::CancelShutdown => {
            info!("Cancelling pending shutdown");
            cancel_shutdown()
        }
        Command::Ping => {
            info!("Ping received");
            Ok(())
        }
        Command::GetMacAddress => {
            // This is handled separately in the server
            Ok(())
        }
    }
}

/// Execute shutdown or restart using the native Windows shutdown API
fn execute_shutdown(restart: bool, force: bool, delay_sec: u16) -> Result<(), ExecutionError> {
    #[cfg(windows)]
    {
        enable_shutdown_privilege()?;

        let reason =
            SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_MAINTENANCE | SHTDN_REASON_FLAG_PLANNED;
        let mut flags = if restart {
            SHUTDOWN_RESTART
        } else {
            SHUTDOWN_POWEROFF
        };

        if force {
            flags |= SHUTDOWN_FORCE_SELF | SHUTDOWN_FORCE_OTHERS;
        }

        let message = if restart {
            to_wide("Remote restart via reboot-agent")
        } else {
            to_wide("Remote shutdown via reboot-agent")
        };

        let result = unsafe {
            InitiateShutdownW(
                PCWSTR::null(),
                PCWSTR(message.as_ptr()),
                u32::from(delay_sec),
                flags,
                reason,
            )
        };

        if result == ERROR_SUCCESS.0 {
            info!(
                "Shutdown API scheduled successfully (restart={}, force={}, delay={}s)",
                restart, force, delay_sec
            );
            Ok(())
        } else {
            let error = WIN32_ERROR(result);
            error!(
                "Shutdown API failed (restart={}, force={}, delay={}s, code={}): {}",
                restart,
                force,
                delay_sec,
                error.0,
                describe_win32_error(error)
            );
            Err(map_win32_error(
                if restart {
                    "failed to schedule system restart"
                } else {
                    "failed to schedule system shutdown"
                },
                error,
            ))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = (restart, force, delay_sec);
        Err(ExecutionError::NotSupported)
    }
}

/// Cancel a pending shutdown
fn cancel_shutdown() -> Result<(), ExecutionError> {
    #[cfg(windows)]
    {
        enable_shutdown_privilege()?;

        match unsafe { AbortSystemShutdownW(PCWSTR::null()) } {
            Ok(()) => {
                info!("Shutdown cancelled successfully");
                Ok(())
            }
            Err(_) => {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_SHUTDOWN_IN_PROGRESS {
                    info!("No shutdown to cancel");
                    Ok(())
                } else {
                    error!(
                        "Failed to cancel shutdown (code={}): {}",
                        error.0,
                        describe_win32_error(error)
                    );
                    Err(map_win32_error("failed to cancel shutdown", error))
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        Err(ExecutionError::NotSupported)
    }
}

#[cfg(windows)]
fn enable_shutdown_privilege() -> Result<(), ExecutionError> {
    let mut token = HANDLE::default();

    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|_| {
            let error = GetLastError();
            error!(
                "Failed to open process token for shutdown privilege (code={}): {}",
                error.0,
                describe_win32_error(error)
            );
            map_win32_error("failed to open process token", error)
        })?;

        let result = (|| {
            let mut luid = Default::default();
            LookupPrivilegeValueW(PCWSTR::null(), SE_SHUTDOWN_NAME, &mut luid).map_err(|_| {
                let error = GetLastError();
                error!(
                    "Failed to lookup shutdown privilege (code={}): {}",
                    error.0,
                    describe_win32_error(error)
                );
                map_win32_error("failed to lookup shutdown privilege", error)
            })?;

            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            SetLastError(ERROR_SUCCESS);
            AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).map_err(|_| {
                let error = GetLastError();
                error!(
                    "Failed to adjust shutdown privilege (code={}): {}",
                    error.0,
                    describe_win32_error(error)
                );
                map_win32_error("failed to enable shutdown privilege", error)
            })?;

            let error = GetLastError();
            if error == ERROR_NOT_ALL_ASSIGNED {
                error!(
                    "Shutdown privilege was not assigned to the current token (code={}): {}",
                    error.0,
                    describe_win32_error(error)
                );
                return Err(map_win32_error(
                    "shutdown privilege is not assigned to the current process",
                    error,
                ));
            }

            Ok(())
        })();

        let _ = CloseHandle(token);
        result
    }
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn describe_win32_error(error: WIN32_ERROR) -> String {
    io::Error::from_raw_os_error(error.0 as i32).to_string()
}

#[cfg(windows)]
fn map_win32_error(action: &str, error: WIN32_ERROR) -> ExecutionError {
    let detail = describe_win32_error(error);

    if error == ERROR_ACCESS_DENIED || error == ERROR_NOT_ALL_ASSIGNED {
        ExecutionError::CommandFailed(format!(
            "{}: {}. Run reboot-agent as administrator.",
            action, detail
        ))
    } else {
        ExecutionError::CommandFailed(format!("{}: {} (Win32 error {})", action, detail, error.0))
    }
}

/// Get the primary MAC address of the machine
#[cfg(windows)]
pub fn get_mac_address() -> Result<[u8; 6], ExecutionError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    // First call to get required buffer size
    let mut size: u32 = 0;
    unsafe {
        GetAdaptersAddresses(AF_UNSPEC.0 as u32, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut size);
    }

    if size == 0 {
        return Err(ExecutionError::SystemError(
            "Failed to get adapter info size".into(),
        ));
    }

    // Allocate buffer
    let mut buffer = vec![0u8; size as usize];
    let adapters = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    // Second call to get actual data
    let result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapters),
            &mut size,
        )
    };

    if result != 0 {
        return Err(ExecutionError::SystemError(format!(
            "GetAdaptersAddresses failed: {}",
            result
        )));
    }

    // Iterate through adapters to find one with a valid MAC
    let mut current = adapters;
    while !current.is_null() {
        let adapter = unsafe { &*current };

        // Check if this adapter has a valid physical address (MAC)
        if adapter.PhysicalAddressLength == 6 {
            // Skip loopback and other virtual adapters
            let adapter_type = adapter.IfType;
            // 6 = Ethernet, 71 = WiFi
            if adapter_type == 6 || adapter_type == 71 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&adapter.PhysicalAddress[..6]);

                // Skip all-zero MAC
                if mac != [0u8; 6] {
                    info!(
                        "Found MAC address: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    );
                    return Ok(mac);
                }
            }
        }

        current = adapter.Next;
    }

    Err(ExecutionError::SystemError(
        "No suitable network adapter found".into(),
    ))
}

/// Get MAC address (non-Windows stub)
#[cfg(not(windows))]
pub fn get_mac_address() -> Result<[u8; 6], ExecutionError> {
    // Return a dummy MAC for testing on non-Windows
    Ok([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_mac_address() {
        // This test will only work on Windows with a network adapter
        let result = get_mac_address();
        println!("MAC result: {:?}", result);
        // Don't assert success as it depends on the machine
    }
}
