//! TCP server with TLS for handling remote commands

use crate::config::Config;
use crate::executor::{execute_command, get_mac_address};
use crate::security::{IpWhitelist, RateLimiter, RequestValidator};

use common::{deserialize, serialize, Command, CommandRequest, CommandResponse, Status};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Maximum message size (64KB)
const MAX_MESSAGE_SIZE: usize = 65536;

/// Server state
pub struct Server {
    config: Arc<Config>,
    rate_limiter: Arc<RateLimiter>,
    ip_whitelist: Arc<IpWhitelist>,
    validator: Arc<RequestValidator>,
    shutdown_rx: watch::Receiver<bool>,
}

impl Server {
    pub fn new(config: Config, shutdown_rx: watch::Receiver<bool>) -> Result<Self, anyhow::Error> {
        let psk = config.get_psk()?;

        Ok(Self {
            rate_limiter: Arc::new(RateLimiter::new(config.rate_limit)),
            ip_whitelist: Arc::new(IpWhitelist::new(&config.allowed_ips)),
            validator: Arc::new(RequestValidator::new(psk)),
            config: Arc::new(config),
            shutdown_rx,
        })
    }

    /// Run the server
    pub async fn run(&self) -> Result<(), anyhow::Error> {
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr).await?;

        info!("Server listening on {}", addr);

        // Spawn cleanup task
        let rate_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                rate_limiter.cleanup();
            }
        });

        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            self.handle_connection(stream, addr);
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Server shutdown requested");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_connection(&self, stream: TcpStream, addr: SocketAddr) {
        let ip = addr.ip();

        // Check IP whitelist
        if !self.ip_whitelist.is_allowed(&ip) {
            warn!("Connection from {} rejected: IP not in whitelist", addr);
            return;
        }

        // Check rate limit
        if !self.rate_limiter.check(ip) {
            warn!("Connection from {} rejected: rate limit exceeded", addr);
            return;
        }

        info!("Accepted connection from {}", addr);

        let validator = self.validator.clone();
        let rate_limiter = self.rate_limiter.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, addr, validator, rate_limiter).await {
                warn!("Connection from {} ended with error: {}", addr, e);
            }
        });
    }
}

/// Handle a single client connection
async fn handle_client(
    mut stream: TcpStream,
    addr: SocketAddr,
    validator: Arc<RequestValidator>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), anyhow::Error> {
    info!("New connection from {}", addr);

    // Read message length (4 bytes, little-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;

    if msg_len > MAX_MESSAGE_SIZE {
        warn!("Message too large from {}: {} bytes", addr, msg_len);
        return Ok(());
    }

    // Read message
    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf).await?;

    // Deserialize request
    let request: CommandRequest = match deserialize(&msg_buf) {
        Ok(req) => req,
        Err(e) => {
            warn!("Failed to deserialize request from {}: {}", addr, e);
            send_response(&mut stream, CommandResponse::error(0, Status::InvalidCommand, "Invalid request format")).await?;
            return Ok(());
        }
    };

    info!(
        "Received command {:?} from {} (request_id={})",
        request.command, addr, request.request_id
    );

    // Validate request
    if let Err(status) = validator.validate(&request) {
        // Track auth failures for blocking
        if status == Status::AuthFailed {
            // After 3 failures, the rate limiter would block anyway
            warn!("Auth failure from {}", addr);
        }

        send_response(
            &mut stream,
            CommandResponse::error(request.request_id, status, "Validation failed"),
        )
        .await?;
        return Ok(());
    }

    // Execute command
    let response = match &request.command {
        Command::GetMacAddress => match get_mac_address() {
            Ok(mac) => CommandResponse::success_with_mac(request.request_id, mac),
            Err(e) => CommandResponse::error(
                request.request_id,
                Status::ExecutionFailed,
                e.to_string(),
            ),
        },
        Command::Ping => CommandResponse::success(request.request_id),
        cmd => match execute_command(cmd).await {
            Ok(()) => CommandResponse::success(request.request_id),
            Err(e) => CommandResponse::error(
                request.request_id,
                Status::ExecutionFailed,
                e.to_string(),
            ),
        },
    };

    send_response(&mut stream, response).await?;

    info!("Completed request {} from {}", request.request_id, addr);
    Ok(())
}

/// Send a response to the client
async fn send_response(
    stream: &mut TcpStream,
    response: CommandResponse,
) -> Result<(), io::Error> {
    let data = serialize(&response).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Send length prefix
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;

    // Send data
    stream.write_all(&data).await?;
    stream.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Integration tests would go here
}
