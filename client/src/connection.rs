//! Network connection to the agent

use common::{deserialize, serialize, Command, CommandRequest, CommandResponse, Status};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{error, info};

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Read/write timeout
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Client connection to the agent
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    psk: [u8; 32],
}

impl Connection {
    /// Connect to an agent
    pub async fn connect(addr: &str, psk: [u8; 32]) -> Result<Self, io::Error> {
        info!("Connecting to {}", addr);

        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Connection timeout"))?
            .map_err(|e| {
                error!("Connection failed: {}", e);
                e
            })?;

        info!("Connected to {}", addr);

        Ok(Self { stream, psk })
    }

    /// Send a command and wait for response
    pub async fn send_command(&mut self, command: Command) -> Result<CommandResponse, io::Error> {
        let request = CommandRequest::new(command, &self.psk);

        info!("Sending command (request_id={})", request.request_id);

        // Serialize request
        let data = serialize(&request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Send length prefix
        let len = (data.len() as u32).to_le_bytes();
        timeout(IO_TIMEOUT, self.stream.write_all(&len))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Write timeout"))??;

        // Send data
        timeout(IO_TIMEOUT, self.stream.write_all(&data))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Write timeout"))??;

        timeout(IO_TIMEOUT, self.stream.flush())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Flush timeout"))??;

        // Read response length
        let mut len_buf = [0u8; 4];
        timeout(IO_TIMEOUT, self.stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Read timeout"))??;

        let msg_len = u32::from_le_bytes(len_buf) as usize;

        // Read response
        let mut msg_buf = vec![0u8; msg_len];
        timeout(IO_TIMEOUT, self.stream.read_exact(&mut msg_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Read timeout"))??;

        // Deserialize response
        let response: CommandResponse = deserialize(&msg_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        info!(
            "Received response: status={:?}, request_id={}",
            response.status, response.request_id
        );

        Ok(response)
    }

    /// Ping the agent
    pub async fn ping(&mut self) -> Result<(), io::Error> {
        let response = self.send_command(Command::Ping).await?;
        if response.status == Status::Success {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                response.message.unwrap_or_else(|| "Ping failed".into()),
            ))
        }
    }

    /// Get the agent's MAC address
    pub async fn get_mac_address(&mut self) -> Result<[u8; 6], io::Error> {
        let response = self.send_command(Command::GetMacAddress).await?;

        match (response.status, response.mac_address) {
            (Status::Success, Some(mac)) => Ok(mac),
            (Status::Success, None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No MAC address in response",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                response
                    .message
                    .unwrap_or_else(|| "Failed to get MAC".into()),
            )),
        }
    }

    /// Send shutdown command
    pub async fn shutdown(&mut self, force: bool, delay_sec: u16) -> Result<(), io::Error> {
        let response = self
            .send_command(Command::Shutdown { force, delay_sec })
            .await?;

        if response.status == Status::Success {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                response
                    .message
                    .unwrap_or_else(|| "Shutdown failed".into()),
            ))
        }
    }

    /// Send restart command
    pub async fn restart(&mut self, force: bool, delay_sec: u16) -> Result<(), io::Error> {
        let response = self
            .send_command(Command::Restart { force, delay_sec })
            .await?;

        if response.status == Status::Success {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                response.message.unwrap_or_else(|| "Restart failed".into()),
            ))
        }
    }

    /// Cancel pending shutdown
    pub async fn cancel_shutdown(&mut self) -> Result<(), io::Error> {
        let response = self.send_command(Command::CancelShutdown).await?;

        if response.status == Status::Success {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                response
                    .message
                    .unwrap_or_else(|| "Cancel failed".into()),
            ))
        }
    }
}
