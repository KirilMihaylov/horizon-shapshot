use std::{
    cmp::Ordering,
    fs::File as FileSync,
    future::Future,
    io::{stdin, stdout, Error as IOError, Read, SeekFrom, Stdout, StdoutLock, Write},
    pin::Pin,
    string::FromUtf8Error,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use sha2::{
    digest::{consts::U64, generic_array::GenericArray},
    Digest, Sha256, Sha512,
};
use tokio::{
    fs::{read_dir, File, ReadDir},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    macros::support::poll_fn,
    net::{TcpListener, TcpStream},
    pin, spawn,
    task::JoinHandle,
    time::timeout,
};
use tokio_native_tls::{
    native_tls::{Error as TlsError, Identity, Protocol, TlsAcceptor as TlsAcceptorSync},
    TlsAcceptor, TlsStream,
};

#[tokio::main]
async fn main() -> Result<(), String> {
    poll_fn(main_loop).await
}

async fn console() -> Result<(), IOError> {
    loop {
        let mut line: String = String::new();

        stdin().read_line(&mut line)?;

        let line: &str = line.trim();

        if line == "" {
        } else if line == "exit" {
            break;
        } else {
            let stdout: Stdout = stdout();

            let mut stdout: StdoutLock = stdout.lock();

            stdout.write_all(b"Unknown command!\n")?;

            stdout.flush()?;
        }
    }

    Ok(())
}

fn build_listener(cx: &mut Context) -> Result<TcpListener, String> {
    pin!(
        let future = TcpListener::bind(
                    option_env!("BIND")
                        .ok_or("No bind address provided! /Environment variable: BIND/")?
        );
    );

    loop {
        break match future.as_mut().poll(cx) {
            Poll::Ready(Ok(listener)) => Ok(listener),
            Poll::Ready(Err(error)) => Err(error.to_string()),
            Poll::Pending => continue,
        };
    }
}

fn build_acceptor() -> Result<TlsAcceptor, String> {
    Ok(TlsAcceptor::from(
        TlsAcceptorSync::builder(
            Identity::from_pkcs12(
                {
                    let mut file: FileSync = FileSync::open(option_env!("CERT_PATH").ok_or(
                        "No certificate path provided! /Environment variable: CERT_PATH/",
                    )?)
                    .map_err(|error: IOError| error.to_string())?;

                    let mut content: Vec<u8> = Vec::new();

                    file.read_to_end(&mut content)
                        .map_err(|error: IOError| error.to_string())?;

                    content
                }
                .as_slice(),
                option_env!("CERT_PASS")
                    .ok_or("No certificate password provided! /Environment variable: CERT_PASS/")?,
            )
            .map_err(|error: TlsError| error.to_string())?,
        )
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(None)
        .build()
        .map_err(|error: TlsError| error.to_string())?,
    ))
}

fn main_loop(cx: &mut Context) -> Poll<Result<(), String>> {
    let listener: TcpListener = build_listener(cx)?;

    let acceptor: Arc<TlsAcceptor> = Arc::new(build_acceptor()?);

    let host_directory: &'static str = option_env!("HOST_DIR")
        .ok_or("No host directory provided! /Environment variable: HOST_DIR/")?;

    let server_password_hash: GenericArray<u8, U64> = {
        let mut digest: Sha512 = Sha512::default();

        digest.update(
            option_env!("SERVER_PASS")
                .ok_or("No server password provided! /Environment variable: SERVER_PASS/")?
                .as_bytes(),
        );

        digest.finalize()
    };

    let mut console: JoinHandle<()> = spawn(async {
        if let Err(error) = console().await {
            eprintln!("[ERROR] {}", error.to_string());
        }
    });

    let mut console: Pin<&mut JoinHandle<()>> = Pin::new(&mut console);

    loop {
        if matches!(console.as_mut().poll(cx), Poll::Ready(Ok(()))) {
            break Poll::Ready(Ok(()));
        }

        if let Poll::Ready(Ok((stream, address))) = listener.poll_accept(cx) {
            let acceptor: Arc<TlsAcceptor> = acceptor.clone();

            spawn(async move {
                let mut stream: TlsStream<TcpStream> = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!(
                            "[ERROR] Couldn't begin TLS communication with {}! Error message: {}.",
                            address,
                            error.to_string()
                        );

                        return Err("Couldn't begin TLS communication!");
                    }
                };

                if !matches!(
                    timeout(Duration::from_millis(2500), async {
                        let length: u8 = stream.read_u8().await?;

                        let mut buf: [u8; 255] = [0; 255];

                        let buf: &mut [u8] = &mut buf[..length as usize];

                        stream.read_exact(buf).await?;

                        let client_hash: GenericArray<u8, U64> = {
                            let mut client_digest: Sha512 = Sha512::default();

                            client_digest.update(buf);

                            client_digest.finalize()
                        };

                        Ok::<bool, IOError>(server_password_hash == client_hash)
                    })
                    .await,
                    Ok(Ok(true))
                ) {
                    eprintln!("[ERROR] Couldn't verify password from {}!", address);

                    return Err("Couldn't verify password!");
                }

                spawn(handle_client_loop(stream, host_directory));

                Ok(())
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Command {
    KeepAlive,
    List,
    GoToRootDirectory,
    EnterDirectory(String),
    LeaveDirectory,
    DownloadFile(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DownloadSubcommand {
    KeepAlive,
    List { size: u16 },
    ChunkHash { index: u64, size: u16 },
    DownloadChunk { index: u64, size: u16 },
    CloseFile,
}

fn validate_path_segment(segment: &str) -> bool {
    segment.chars().all(|character: char| {
        character.is_alphanumeric()
            || [
                ' ', '\t', '.', '-', '_', '=', '~', '!', ',', '(', ')', '[', ']', '{', '}',
            ]
            .contains(&character)
    }) && segment != ".."
}

async fn read_string(stream: &mut TlsStream<TcpStream>) -> Result<String, String> {
    let length: u16 = stream
        .read_u16_le()
        .await
        .map_err(|error: IOError| error.to_string())?;

    let mut buffer: Vec<u8> = vec![0; length as usize];

    stream
        .read_exact(&mut buffer)
        .await
        .map_err(|error: IOError| error.to_string())?;

    String::from_utf8(buffer).map_err(|error: FromUtf8Error| error.to_string())
}

async fn write_string<'a, 'b>(
    stream: &'a mut TlsStream<TcpStream>,
    string: &'b str,
) -> Result<(), String> {
    stream
        .write_u16_le(TryInto::<u16>::try_into(string.len()).map_err(|_| String::new())?)
        .await
        .map_err(|error: IOError| error.to_string())?;

    stream
        .write_all(string.as_bytes())
        .await
        .map_err(|error: IOError| error.to_string())?;

    Ok(())
}

async fn read_client_command(stream: &mut TlsStream<TcpStream>) -> Result<Command, String> {
    let command_byte: u8 = stream
        .read_u8()
        .await
        .map_err(|error: IOError| error.to_string())?;

    Ok(match command_byte {
        0 => Command::KeepAlive,
        1 => Command::List,
        2 => Command::GoToRootDirectory,
        3 => Command::EnterDirectory(read_string(stream).await?),
        4 => Command::LeaveDirectory,
        5 => Command::DownloadFile(read_string(stream).await?),
        _ => return Err(String::from("Client sent unknown command!")),
    })
}

async fn read_client_download_subcommand(
    stream: &mut TlsStream<TcpStream>,
) -> Result<DownloadSubcommand, String> {
    async fn read_chunk_size(stream: &mut TlsStream<TcpStream>) -> Result<u16, String> {
        let chunk_size: u16 = stream
            .read_u16_le()
            .await
            .map_err(|error: IOError| error.to_string())?;

        if chunk_size == 0 {
            Err(String::from("Client specified zero as chunk size!"))
        } else {
            Ok(chunk_size)
        }
    }

    let command_byte: u8 = stream
        .read_u8()
        .await
        .map_err(|error: IOError| error.to_string())?;

    Ok(match command_byte {
        0 => DownloadSubcommand::KeepAlive,
        1 => DownloadSubcommand::List {
            size: read_chunk_size(stream).await?,
        },
        2 => DownloadSubcommand::ChunkHash {
            index: {
                let mut buffer: [u8; 8] = [0; 8];

                stream
                    .read_exact(&mut buffer[..7])
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                u64::from_le_bytes(buffer)
            },
            size: read_chunk_size(stream).await?,
        },
        3 => DownloadSubcommand::DownloadChunk {
            index: {
                let mut buffer: [u8; 8] = [0; 8];

                stream
                    .read_exact(&mut buffer[..7])
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                u64::from_le_bytes(buffer)
            },
            size: read_chunk_size(stream).await?,
        },
        4 => DownloadSubcommand::CloseFile,
        _ => return Err(String::from("Client sent unknown download command!")),
    })
}

async fn list_directory(
    stream: &mut TlsStream<TcpStream>,
    effective_path: &str,
) -> Result<(), String> {
    let mut list: Vec<(bool, String)> = Vec::new();

    let mut read_dir: ReadDir = match read_dir(&effective_path).await {
        Ok(read_dir) => read_dir,
        Err(error) => {
            eprintln!(
                "[ERROR] Failed to read directory '{}'! Error message: {}",
                effective_path, error
            );

            stream
                .write_u8(0xFF)
                .await
                .map_err(|error: IOError| error.to_string())?;

            return Ok(());
        }
    };

    while list.len() < 0xFFFF_FFFF {
        match read_dir.next_entry().await {
            Ok(Some(entry)) => {
                let name: String = entry.file_name().to_string_lossy().to_string();

                if 0xFFFF < name.as_bytes().len() || !validate_path_segment(&name) {
                    continue;
                }

                list.push((
                    match entry.file_type().await {
                        Ok(file_type) if file_type.is_file() => false,
                        Ok(file_type) if file_type.is_dir() => true,
                        Ok(_) => continue,
                        Err(_) => {
                            eprintln!(
                                "[ERROR] Couldn't get file type of '{}'!",
                                entry.file_name().to_string_lossy()
                            );

                            continue;
                        }
                    },
                    name,
                ));
            }
            Ok(None) => break,
            Err(_) => {
                eprintln!("[ERROR] Failed to read directory '{}'!", effective_path);

                stream
                    .write_u8(1)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                continue;
            }
        }
    }

    stream
        .write_u8(0)
        .await
        .map_err(|error: IOError| error.to_string())?;

    stream
        .write_u32_le(list.len() as u32)
        .await
        .map_err(|error: IOError| error.to_string())?;

    for (is_directory, name) in list {
        stream
            .write_u8(is_directory as u8)
            .await
            .map_err(|error: IOError| error.to_string())?;

        write_string(stream, &name).await?;
    }

    Ok(())
}

async fn client_download_file(
    stream: &mut TlsStream<TcpStream>,
    effective_path: &str,
    name: &str,
) -> Result<(), String> {
    let name: String = String::from(effective_path) + "/" + name;

    let mut file: File = File::open(&name)
        .await
        .map_err(|error: IOError| error.to_string())?;

    let length: u64 = match file.metadata().await {
        Ok(metadata) => {
            stream
                .write_u8(0)
                .await
                .map_err(|error: IOError| error.to_string())?;

            stream
                .write_u64_le(metadata.len())
                .await
                .map_err(|error: IOError| error.to_string())?;

            metadata.len()
        }
        Err(error) => {
            eprintln!(
                "[ERROR] Couldn't get metadata of file '{}'! Error message: {}",
                name, error
            );

            stream
                .write_u8(0xFF)
                .await
                .map_err(|error: IOError| error.to_string())?;

            return Ok(());
        }
    };

    loop {
        match read_client_download_subcommand(stream).await? {
            DownloadSubcommand::KeepAlive => stream
                .write_u8(0)
                .await
                .map_err(|error: IOError| error.to_string())?,
            DownloadSubcommand::List { size } => {
                let chunk_size: u32 = (size as u32).wrapping_shl(4);

                stream
                    .write_u8(0)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                stream
                    .write_all(&(length / chunk_size as u64).to_le_bytes()[..7])
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                {
                    let last_chunk_size: [u8; 4] =
                        ((length % chunk_size as u64) as u32).to_le_bytes();

                    stream
                        .write_all(&last_chunk_size[..3])
                        .await
                        .map_err(|error: IOError| error.to_string())?;
                }
            }
            DownloadSubcommand::ChunkHash { index, size } => {
                let chunk_size: u32 = (size as u32).wrapping_shl(4);

                file.seek(SeekFrom::Start(index.wrapping_mul(chunk_size as u64)))
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                let chunks: u64 = length / chunk_size as u64;

                let mut buffer: Box<[u8]> = vec![
                    0;
                    match index.cmp(&chunks) {
                        Ordering::Less => {
                            chunk_size as usize
                        }
                        Ordering::Equal => {
                            (length % chunk_size as u64) as usize
                        }
                        Ordering::Greater => {
                            return Err(String::from("Client sent chunk index beyond file size!"));
                        }
                    }
                ]
                .into_boxed_slice();

                file.read_exact(&mut buffer)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                stream
                    .write_u8(0)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                let mut digest: Sha256 = Sha256::new();

                digest.update(&buffer);

                stream
                    .write_all(&digest.finalize())
                    .await
                    .map_err(|error: IOError| error.to_string())?;
            }
            DownloadSubcommand::DownloadChunk { index, size } => {
                let chunk_size: u32 = (size as u32).wrapping_shl(4);

                file.seek(SeekFrom::Start(index.wrapping_mul(chunk_size as u64)))
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                let mut buffer: Box<[u8]> = vec![
                    0;
                    match index.cmp(&(length / chunk_size as u64)) {
                        Ordering::Less => chunk_size as usize,
                        Ordering::Equal => (length % chunk_size as u64) as usize,
                        Ordering::Greater =>
                            return Err(String::from("Client sent chunk index beyond file size!")),
                    }
                ]
                .into_boxed_slice();

                file.read_exact(&mut buffer)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                stream
                    .write_u8(0)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                stream
                    .write_all(&buffer.len().to_le_bytes()[..3])
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                stream
                    .write_all(&buffer)
                    .await
                    .map_err(|error: IOError| error.to_string())?;
            }
            DownloadSubcommand::CloseFile => {
                stream
                    .write_u8(0)
                    .await
                    .map_err(|error: IOError| error.to_string())?;

                break;
            }
        }
    }

    Ok(())
}

async fn handle_client_loop(
    mut stream: TlsStream<TcpStream>,
    host_directory: &'static str,
) -> Result<(), String> {
    stream
        .write_u8(0)
        .await
        .map_err(|error: IOError| error.to_string())?;

    stream
        .flush()
        .await
        .map_err(|error: IOError| error.to_string())?;

    fn build_effective_path(host_directory: &'static str, path: &[String]) -> String {
        path.iter().fold(
            String::from(
                if let Some(host_directory) = host_directory.strip_suffix('/') {
                    host_directory
                } else {
                    host_directory
                },
            ),
            |acc: String, element: &String| acc + "/" + element,
        )
    }

    let mut path: Vec<String> = Vec::new();

    let mut effective_path: String = build_effective_path(host_directory, &path);

    while let Ok(Ok(command)) =
        timeout(Duration::from_secs(600), read_client_command(&mut stream)).await
    {
        match command {
            Command::KeepAlive => (),
            Command::List => list_directory(&mut stream, &effective_path).await?,
            Command::GoToRootDirectory => {
                path.clear();

                effective_path = build_effective_path(host_directory, &path);

                stream
                    .write_u8(0)
                    .await
                    .map_err(|error: IOError| error.to_string())?;
            }
            Command::EnterDirectory(name) if validate_path_segment(&name) => {
                path.push(name);

                let temporary_effective_path: String = build_effective_path(host_directory, &path);

                stream
                    .write_u8(if read_dir(&temporary_effective_path).await.is_ok() {
                        effective_path = temporary_effective_path;

                        0
                    } else {
                        eprintln!(
                            "[ERROR] Client requested folder which cannot be read! Path: {}",
                            temporary_effective_path
                        );

                        path.pop();

                        0xFF
                    })
                    .await
                    .map_err(|error: IOError| error.to_string())?;
            }
            Command::LeaveDirectory => {
                stream
                    .write_u8(if path.pop().is_some() {
                        effective_path = build_effective_path(host_directory, &path);

                        0
                    } else {
                        0xFF
                    })
                    .await
                    .map_err(|error: IOError| error.to_string())?;
            }
            Command::DownloadFile(name) if validate_path_segment(&name) => {
                client_download_file(&mut stream, &effective_path, &name).await?
            }
            _ => stream
                .write_u8(0xFF)
                .await
                .map_err(|error: IOError| error.to_string())?,
        }
    }

    Ok(())
}
