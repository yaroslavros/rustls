use std::error::Error;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.0\r\nHost: testserver.com\r\n\r\n";
const IO_TIMEOUT: Duration = Duration::from_millis(200);
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value_t = 1)]
    initiator_count: usize,

    #[arg(long)]
    no_initiator: bool,

    #[arg(long, default_value_t = 0)]
    eku_after: usize,

    #[arg(long, default_value_t = 1)]
    eku_updates: usize,

    #[arg(long, default_value_t = 0)]
    appdata_seconds: u64,

    host: String,
    port: u16,
    ca_cert: PathBuf,
    server_name: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let config = Arc::new(make_config(&args.ca_cert)?);
    let server_name = ServerName::try_from(args.server_name.clone())?.to_owned();

    let mut socket = TcpStream::connect((args.host.as_str(), args.port))?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    socket.set_nodelay(true)?;

    let mut conn = ClientConnection::new(config, server_name)?;
    handshake(&mut conn, &mut socket)?;
    eprintln!("handshake complete");

    if !args.no_initiator && args.eku_after == 0 {
        for idx in 0..args.initiator_count {
            eprintln!("running immediate EKU {}", idx + 1);
            run_eku(&mut conn, &mut socket)?;
        }
    }

    let mut exchanges_done = 0usize;
    if args.appdata_seconds > 0 {
        let deadline = Instant::now() + Duration::from_secs(args.appdata_seconds);
        while Instant::now() < deadline {
            eprintln!("starting timed exchange {}", exchanges_done + 1);
            exchange_http(&mut conn, &mut socket)?;
            exchanges_done += 1;
            eprintln!("finished timed exchange {}", exchanges_done);
            maybe_run_scheduled_eku(&args, &mut conn, &mut socket, exchanges_done)?;
        }
    } else {
        let exchanges = if args.no_initiator { 2 } else { 2 };
        for idx in 0..exchanges {
            eprintln!("starting exchange {}", idx + 1);
            exchange_http(&mut conn, &mut socket)?;
            exchanges_done += 1;
            eprintln!("finished exchange {}", exchanges_done);
            maybe_run_scheduled_eku(&args, &mut conn, &mut socket, exchanges_done)?;
        }
    }

    eprintln!("sending close_notify");
    conn.send_close_notify();
    flush_tls(&mut conn, &mut socket)?;
    Ok(())
}

fn make_config(ca_cert: &PathBuf) -> Result<ClientConfig, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(ca_cert)?
        .collect::<Result<Vec<_>, _>>()?;
    let (_, invalid) = roots.add_parsable_certificates(certs);
    if invalid != 0 {
        return Err(format!("failed to parse {invalid} certificate(s) from {}", ca_cert.display()).into());
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.extended_key_update = true;
    Ok(config)
}

fn handshake(conn: &mut ClientConnection, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while conn.is_handshaking() {
        progress_io(conn, socket, deadline, "handshake")?;
    }
    Ok(())
}

fn exchange_http(conn: &mut ClientConnection, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    conn.writer()
        .write_all(HTTP_REQUEST)
        .map_err(|err| format!("write request failed: {err:?}"))?;
    flush_tls(conn, socket).map_err(|err| format!("flush request failed: {err}"))?;

    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut response = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        match conn.reader().read(&mut buf) {
            Ok(0) => return Err("connection closed before response completed".into()),
            Ok(read) => {
                response.extend_from_slice(&buf[..read]);
                if response.ends_with(b"\n") {
                    break;
                }
                continue;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(format!("read response failed: {err:?}").into()),
        }

        progress_io(conn, socket, deadline, "appdata exchange")
            .map_err(|err| format!("drive response IO failed: {err}"))?;
    }

    if !response.starts_with(b"HTTP/1.0 200 OK") {
        return Err(format!("unexpected HTTP response: {}", String::from_utf8_lossy(&response)).into());
    }

    Ok(())
}

fn maybe_run_scheduled_eku(
    args: &Args,
    conn: &mut ClientConnection,
    socket: &mut TcpStream,
    exchanges_done: usize,
) -> Result<(), Box<dyn Error>> {
    if args.no_initiator || args.eku_after == 0 {
        return Ok(());
    }

    if exchanges_done % args.eku_after != 0 {
        return Ok(());
    }

    for _ in 0..args.eku_updates {
        run_eku(conn, socket)?;
    }

    Ok(())
}

fn run_eku(conn: &mut ClientConnection, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    conn.refresh_traffic_keys()?;
    flush_tls(conn, socket)?;

    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut saw_progress = false;
    loop {
        match try_progress_io(conn, socket, deadline)? {
            Progress::Advanced => saw_progress = true,
            Progress::Idle if saw_progress && !conn.wants_write() => break,
            Progress::Idle => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for EKU completion".into());
                }
            }
        }
    }

    eprintln!("EKU completed");
    Ok(())
}

fn flush_tls(conn: &mut ClientConnection, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while conn.wants_write() {
        progress_io(conn, socket, deadline, "flush")?;
    }
    Ok(())
}

fn progress_io(
    conn: &mut ClientConnection,
    socket: &mut TcpStream,
    deadline: Instant,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    match try_progress_io(conn, socket, deadline)? {
        Progress::Advanced => Ok(()),
        Progress::Idle => Err(format!("timed out while waiting for {context}").into()),
    }
}

fn try_progress_io(
    conn: &mut ClientConnection,
    socket: &mut TcpStream,
    deadline: Instant,
) -> Result<Progress, Box<dyn Error>> {
    if Instant::now() >= deadline {
        return Ok(Progress::Idle);
    }

    match conn.complete_io(socket) {
        Ok((read_bytes, written_bytes)) => {
            if read_bytes == 0 && written_bytes == 0 {
                Ok(Progress::Idle)
            } else {
                Ok(Progress::Advanced)
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(Progress::Idle)
        }
        Err(err) => Err(err.into()),
    }
}

enum Progress {
    Advanced,
    Idle,
}
