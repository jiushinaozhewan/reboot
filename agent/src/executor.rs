//! Command executor for Windows system operations

use common::{Command, ExecutionError};
use std::process::Command as ProcessCommand;
use tracing::{error, info};

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

/// Execute shutdown or restart using shutdown.exe
fn execute_shutdown(restart: bool, force: bool, delay_sec: u16) -> Result<(), ExecutionError> {
    let mut cmd = ProcessCommand::new("shutdown");

    // /s = shutdown, /r = restart
    if restart {
        cmd.arg("/r");
    } else {
        cmd.arg("/s");
    }

    // /t = timeout in seconds
    cmd.args(["/t", &delay_sec.to_string()]);

    // /f = force close applications
    if force {
        cmd.arg("/f");
    }

    // /c = comment (optional, for logging)
    cmd.args(["/c", "Remote shutdown via reboot-agent"]);

    let output = cmd.output().map_err(|e| {
        error!("Failed to execute shutdown command: {}", e);
        ExecutionError::CommandFailed(e.to_string())
    })?;

    if output.status.success() {
        info!("Shutdown command executed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Shutdown command failed: {}", stderr);
        Err(ExecutionError::CommandFailed(stderr.to_string()))
    }
}

/// Cancel a pending shutdown
fn cancel_shutdown() -> Result<(), ExecutionError> {
    let output = ProcessCommand::new("shutdown")
        .arg("/a") // abort
        .output()
        .map_err(|e| ExecutionError::CommandFailed(e.to_string()))?;

    if output.status.success() {
        info!("Shutdown cancelled successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Not having a pending shutdown is not really an error
        if stderr.contains("1116") {
            info!("No shutdown to cancel");
            Ok(())
        } else {
            Err(ExecutionError::CommandFailed(stderr.to_string()))
        }
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
