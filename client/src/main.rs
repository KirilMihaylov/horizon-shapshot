use std::{
    fmt::{Arguments, Display, Formatter, Result as FmtResult},
    fs::File,
    io::{stdin, stdout, Error as IOError, Read, Stdin, Stdout, StdoutLock, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, Mutex, MutexGuard,
        TryLockError::{Poisoned, WouldBlock},
    },
    thread::{sleep, spawn, JoinHandle},
    time::{Duration, Instant},
};

use native_tls::{Protocol, TlsConnector, TlsStream};

fn main() -> Result<(), &'static str> {
    static EXIT: AtomicBool = AtomicBool::new(false);

    let address: String = if let Some(address) = option_env!("ADDRESS") {
        String::from(address)
    } else {
        console_write(format_args!("Enter server's address: "))?;

        console_read_line()?
    };

    let password: String = if let Some(password) = option_env!("PASS") {
        String::from(password)
    } else {
        console_write(format_args!("Enter server's password: "))?;

        console_read_line()?
    };

    console_write_line(format_args!("Connecting to server..."))?;

    let stream: Arc<Mutex<TlsStream<TcpStream>>> =
        Arc::new(Mutex::new(client_connect(&address, &password)?));

    let join_handle: JoinHandle<Result<(), IOError>> = spawn({
        let stream: Arc<Mutex<TlsStream<TcpStream>>> = stream.clone();

        let mut instant: Instant = Instant::now();

        move || -> Result<(), IOError> {
            loop {
                if EXIT.load(SeqCst) {
                    break Ok(());
                }

                if Duration::from_secs(60) < instant.elapsed() {
                    instant = Instant::now();

                    match stream.try_lock() {
                        Ok(mut stream) => {
                            if let Err(error) = stream.write_all(&[0]) {
                                EXIT.store(false, SeqCst);

                                return Err(error);
                            }
                        }
                        Err(WouldBlock) => (),
                        Err(Poisoned(_)) => unreachable!(),
                    }
                }

                sleep(Duration::from_micros(250));
            }
        }
    });

    let mut remote_path: Vec<String> = Vec::new();

    console_write_line(format_args!(
        "For list of supported commands type \"help\"."
    ))?;

    'main_loop: loop {
        console_write(format_args!("{}$ ", Path::new(&remote_path)))?;

        let line: String = console_read_line()?;

        if EXIT.load(SeqCst) {
            break;
        }

        let line: &str = line.trim();

        if line == "" {
            continue;
        }

        if matches!(line, "h" | "?" | "help") {
            console_write_line(format_args!(
                "Supported command:\n\
                \th, ?, help <===> Shows this message.\n\
                \tls, lst, list <===> Lists all files are directories in current folder.\n\
                \trd, root, rootdir <===> Changes the remote working directory to server's root directory.\n\
                \tent <dir>, enter <dir> <===> Changes the remote working directory to the one passed as parameter.\n\
                \tlv, leave <===> Changes the remote working directory to the parent of the current one.\n\
                \tdl, down, download <remote file> <local file> <===> Download a file from the remote working directory to the local one.\n\
                \t\tThis will overwrite the local file, if it already exists!\n\
                \tx, ex, exit <===> Exits while gracefully closing the session."
            ))?;

            continue;
        }

        if matches!(line, "ls" | "lst" | "list") {
            list_directory(&stream)?;

            continue;
        }

        if matches!(line, "rd" | "root" | "rootdir") {
            let mut stream: MutexGuard<TlsStream<TcpStream>> = stream
                .lock()
                .map_err(|_| concat!("Internal error occured! [Poisoned mutex; ", line!(), "]"))?;

            stream
                .write_all(&[2])
                .map_err(|_| "Couldn't write to stream!")?;

            {
                let mut buffer: [u8; 1] = [0];

                stream
                    .read_exact(&mut buffer)
                    .map_err(|_| "Couldn't read from stream!")?;

                if buffer[0] == 0 {
                    remote_path.clear();
                } else {
                    console_write_line(format_args!("Couldn't go to root directory!"))?;
                }
            }

            continue;
        }

        if let Some(mut line) = line.strip_prefix("ent") {
            line = if let Some(line) = line.strip_prefix("er") {
                line
            } else {
                line
            };

            if let Some(folder) = line.strip_prefix(char::is_whitespace) {
                if folder.is_empty() {
                    console_write_line(format_args!(
                        "This command requires a directory as parameter!"
                    ))?;
                } else {
                    let mut stream: MutexGuard<TlsStream<TcpStream>> =
                        stream.lock().map_err(|_| {
                            concat!("Internal error occured! [Poisoned mutex; ", line!(), "]")
                        })?;

                    stream
                        .write_all(&[3])
                        .map_err(|_| "Couldn't write to stream!")?;

                    write_string(&mut stream, folder)?;

                    {
                        let mut buffer: [u8; 1] = [0];

                        stream
                            .read_exact(&mut buffer)
                            .map_err(|_| "Couldn't read from stream!")?;

                        if buffer[0] == 0 {
                            remote_path.push(String::from(folder));
                        } else {
                            console_write_line(format_args!("Couldn't enter directory!"))?;
                        }
                    }
                }

                continue;
            }
        }

        if matches!(line, "lv" | "leave") {
            let mut stream: MutexGuard<TlsStream<TcpStream>> = stream
                .lock()
                .map_err(|_| concat!("Internal error occured! [Poisoned mutex; ", line!(), "]"))?;

            stream
                .write_all(&[4])
                .map_err(|_| "Couldn't write to stream!")?;

            {
                let mut buffer: [u8; 1] = [0];

                stream
                    .read_exact(&mut buffer)
                    .map_err(|_| "Couldn't read from stream!")?;

                if buffer[0] == 0 {
                    remote_path.pop();
                } else {
                    console_write_line(format_args!("Couldn't leave directory!"))?;
                }
            }

            continue;
        }

        if let Some(line) = line
            .strip_prefix("dl")
            .or_else(|| line.strip_prefix("down"))
            .or_else(|| line.strip_prefix("download"))
        {
            if let Some(line) = line.strip_prefix(char::is_whitespace) {
                if line.is_empty() {
                    console_write_line(format_args!(
                        "This command requires two files as parameters!"
                    ))?;
                } else if let Some(position) = line.find(char::is_whitespace) {
                    let remote_file: &str = &line[..position];

                    let local_file: &str = line[position..].trim_start();

                    if local_file.is_empty() {
                        console_write_line(format_args!(
                            "This command requires two files as parameters!"
                        ))?;
                    } else {
                        let mut stream: MutexGuard<TlsStream<TcpStream>> =
                            stream.lock().map_err(|_| {
                                concat!("Internal error occured! [Poisoned mutex; ", line!(), "]")
                            })?;

                        stream
                            .write_all(&[5])
                            .map_err(|_| "Couldn't write to stream!")?;

                        write_string(&mut stream, remote_file)?;

                        {
                            let mut buffer: [u8; 1] = [0];

                            stream
                                .read_exact(&mut buffer)
                                .map_err(|_| "Couldn't read from stream!")?;

                            if buffer[0] != 0 {
                                console_write_line(format_args!("Couldn't retrieve remote file!"))?;

                                continue;
                            }
                        }

                        let length: u64 = {
                            let mut buffer: [u8; 8] = [0; 8];

                            stream
                                .read_exact(&mut buffer)
                                .map_err(|_| "Couldn't read from stream!")?;

                            u64::from_le_bytes(buffer)
                        };

                        let mut file: File = File::create(local_file)
                            .map_err(|_| "Couldn't open local file for writing!")?;

                        let size_format: (f64, &'static str) = if length < 0x400 {
                            (1_f64, "B")
                        } else if length < 0x10_0000 {
                            (1024_f64, "KB")
                        } else if length < 0x4000_0000 {
                            (1048576_f64, "MB")
                        } else if length < 0x100_0000_0000 {
                            (1073741824_f64, "GB")
                        } else {
                            (1099511627776_f64, "TB")
                        };

                        let mut buffer: [u8; 4096] = [0; 4096];

                        for index in 0..(length >> 12) {
                            console_write(format_args!(
                                "\rDownload process: {0:>5.2}% [{1:.2} {3}/{2:.2} {3}]",
                                (index << 12) as f64 * 100_f64 / length as f64,
                                (index << 12) as f64 / size_format.0,
                                length as f64 / size_format.0,
                                size_format.1,
                            ))?;

                            {
                                stream
                                    .write_all(&[3])
                                    .map_err(|_| "Couldn't write to stream!")?;

                                stream
                                    .write_all(&index.to_le_bytes()[..7])
                                    .map_err(|_| "Couldn't write to stream!")?;

                                // Chunk size shifted by 4 to the right;
                                // (4096 = 0x1000) >> 4 = 0x100;
                                // [0, 1] <=> 0x0100 in Little-Endian;
                                stream
                                    .write_all(&[0, 1])
                                    .map_err(|_| "Couldn't write to stream!")?;

                                let mut buffer: [u8; 1] = [0];

                                stream
                                    .read_exact(&mut buffer)
                                    .map_err(|_| "Couldn't read from stream!")?;

                                if buffer[0] != 0 {
                                    stream
                                        .write_all(&[4])
                                        .map_err(|_| "Couldn't write to stream!")?;

                                    let mut buffer: [u8; 1] = [0];

                                    stream
                                        .read_exact(&mut buffer)
                                        .map_err(|_| "Couldn't read from stream!")?;

                                    if buffer[0] != 0 {
                                        dbg!(buffer);

                                        console_write_line(format_args!(
                                        "Failure occured while closing file! Please restart session."
                                    ))?;

                                        return Err(
                                            "Communication error occured while closing file!",
                                        );
                                    }

                                    console_write_line(format_args!(
                                        "Failure occured while downloading file! Please try again."
                                    ))?;

                                    continue 'main_loop;
                                }
                            }

                            stream
                                .read_exact(&mut buffer[..3])
                                .map_err(|_| "Couldn't read from stream!")?;

                            if buffer[..3] != [0, 0x10, 0] {
                                return Err("Server sent chunk with different size than expected!");
                            }

                            stream
                                .read_exact(&mut buffer)
                                .map_err(|_| "Couldn't read from stream!")?;

                            file.write_all(&mut buffer)
                                .map_err(|_| "Couldn't write data to local file!")?;
                        }

                        console_write(format_args!(
                            "\rDownload process: {percentage:>5.2}% [{downloaded:.2} {unit}/{total:.2} {unit}]",
                            percentage = (length & !0xFFF) as f64 * 100_f64 / length as f64,
                            downloaded = (length & !0xFFF) as f64 / size_format.0,
                            total = length as f64 / size_format.0,
                            unit = size_format.1,
                        ))?;

                        {
                            let length: usize = (length & 0xFFF) as usize;

                            if length != 0 {
                                {
                                    stream
                                        .write_all(&[3])
                                        .map_err(|_| "Couldn't write to stream!")?;

                                    stream
                                        .write_all(&(length >> 12).to_le_bytes())
                                        .map_err(|_| "Couldn't write to stream!")?;

                                    // Chunk size shifted by 4 to the right;
                                    // (4096 = 0x1000) >> 4 = 0x100;
                                    // [0, 1] <=> 0x0100 in Little-Endian;
                                    stream
                                        .write_all(&[0, 1])
                                        .map_err(|_| "Couldn't write to stream!")?;

                                    let mut buffer: [u8; 1] = [0];

                                    stream
                                        .read_exact(&mut buffer)
                                        .map_err(|_| "Couldn't read from stream!")?;

                                    if buffer[0] != 0 {
                                        console_write_line(format_args!(
                                            "Failure occured while downloading file! Please try again."
                                        ))?;

                                        continue;
                                    }
                                }

                                if buffer[..3] != [length as u8, (length >> 8) as u8 & 0xF, 0] {
                                    return Err(
                                        "Server sent chunk with different size than expected!",
                                    );
                                }

                                stream
                                    .read_exact(&mut buffer[..length])
                                    .map_err(|_| "Couldn't read from stream!")?;

                                file.write_all(&mut buffer[..length])
                                    .map_err(|_| "Couldn't write data to local file!")?;

                                stream
                                    .write_all(&[4])
                                    .map_err(|_| "Couldn't write to stream!")?;

                                let mut buffer: [u8; 1] = [0];

                                stream
                                    .read_exact(&mut buffer)
                                    .map_err(|_| "Couldn't read from stream!")?;

                                if buffer[0] != 0 {
                                    dbg!(buffer);

                                    console_write_line(format_args!(
                                        "Failure occured while closing file! Please restart session."
                                    ))?;

                                    return Err("Communication error occured while closing file!");
                                }
                            }
                        }

                        console_write_line(format_args!(
                            "\rDownload process: 100.00% [{length:.2} {unit}/{length:.2} {unit}]\nDownload complete.",
                            length = length as f64 / size_format.0,
                            unit = size_format.1
                        ))?;
                    }
                } else {
                    console_write_line(format_args!(
                        "This command requires two files as parameters!"
                    ))?;
                }

                continue;
            }
        }

        if matches!(line, "x" | "ex" | "exit") {
            EXIT.store(true, SeqCst);

            break;
        }

        console_write_line(format_args!(
            "Unknown command! Type \"help\" to learn about the supported commands."
        ))?;
    }

    join_handle
        .join()
        .map_err(|_| "Parallel thread panicked!")?
        .map_err(|_| "Parallel thread couldn't write to stream!")?;

    Ok(())
}

fn console_read_line() -> Result<String, &'static str> {
    let stdin: Stdin = stdin();

    let mut line: String = String::new();

    stdin
        .read_line(&mut line)
        .map_err(|_| "Couldn't read from console!")?;

    for _ in 0..2 {
        if line.ends_with(|c: char| c == '\n' || c == '\r') {
            let _: Option<char> = line.pop();
        }
    }

    Ok(line)
}

fn console_write<'a>(fmt: Arguments<'a>) -> Result<(), &'static str> {
    const MESSAGE: &'static str = "Couldn't read from console!";

    let stdout: Stdout = stdout();

    let mut stdout: StdoutLock = stdout.lock();

    stdout.write_fmt(fmt).map_err(|_| MESSAGE)?;

    stdout.flush().map_err(|_| MESSAGE)?;

    Ok(())
}

fn console_write_line<'a>(fmt: Arguments<'a>) -> Result<(), &'static str> {
    console_write(format_args!("{}\n", fmt))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
struct Path<'a> {
    path: &'a [String],
    slash: bool,
}

impl<'a> Path<'a> {
    pub fn new(path: &'a [String]) -> Self {
        Self { path, slash: true }
    }
}

impl<'a> Iterator for Path<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        Some(if self.slash {
            self.slash = false;

            "/"
        } else {
            let path: &String = self.path.first()?;

            self.path = &self.path[1..];

            self.slash = !self.path.is_empty();

            path
        })
    }
}

impl Display for Path<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for path in *self {
            f.write_str(path)?;
        }

        Ok(())
    }
}

fn read_string(stream: &mut TlsStream<TcpStream>) -> Result<String, &'static str> {
    let mut buffer: [u8; 2] = [0; 2];

    stream
        .read_exact(&mut buffer)
        .map_err(|_| "Couldn't read from stream!")?;

    let length: u16 = u16::from_le_bytes(buffer);

    let mut buffer: Vec<u8> = vec![0; length as usize];

    stream
        .read_exact(&mut buffer)
        .map_err(|_| "Couldn't read from stream!")?;

    String::from_utf8(buffer).map_err(|_| "Invalid UTF-8 string received!")
}

fn write_string<'a, 'b>(
    stream: &'a mut TlsStream<TcpStream>,
    string: &'b str,
) -> Result<(), &'static str> {
    const MESSAGE: &'static str = "Couldn't write to stream!";

    stream
        .write_all(
            &TryInto::<u16>::try_into(string.len())
                .map_err(|_| "String too long! Maximum number of bytes/ASCII characters is 65535!")?
                .to_le_bytes(),
        )
        .map_err(|_| MESSAGE)?;

    stream.write_all(string.as_bytes()).map_err(|_| MESSAGE)?;

    Ok(())
}

fn client_connect(address: &str, password: &str) -> Result<TlsStream<TcpStream>, &'static str> {
    const LOGIN_FAIL_MESSAGE: &'static str =
        "Connection failed! Make sure the address and password are correct!";

    let length: u8 = password
        .as_bytes()
        .len()
        .try_into()
        .map_err(|_| "Password cannot be longer than 255 bytes/ASCII characters long!")?;

    let mut stream: TlsStream<TcpStream> = TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv12))
        .max_protocol_version(None)
        .danger_accept_invalid_certs(cfg!(debug_assertions))
        .danger_accept_invalid_hostnames(cfg!(debug_assertions))
        .build()
        .map_err(|_| "Failure occured while setting up environment for secure communication!")?
        .connect(
            &address,
            TcpStream::connect(address.trim())
                .map_err(|_| "Couldn't connect to server! Make sure the address is correct!")?,
        )
        .map_err(|_| "Failure occured while negotiating secure communication channel!")?;

    stream
        .write_all(&[length])
        .map_err(|_| LOGIN_FAIL_MESSAGE)?;

    stream
        .write_all(password.as_bytes())
        .map_err(|_| LOGIN_FAIL_MESSAGE)?;

    stream.flush().map_err(|_| LOGIN_FAIL_MESSAGE)?;

    // Server responds with a zero byte just to asure the client password is correct.
    {
        let mut buffer: [u8; 1] = [0];

        stream
            .read_exact(&mut buffer)
            .map_err(|_| LOGIN_FAIL_MESSAGE)?;
    }

    Ok(stream)
}

fn list_directory(stream: &Mutex<TlsStream<TcpStream>>) -> Result<(), &'static str> {
    let mut stream: MutexGuard<TlsStream<TcpStream>> = stream
        .lock()
        .map_err(|_| concat!("Internal error occured! [Poisoned mutex; ", line!(), "]"))?;

    stream
        .write_all(&[1])
        .map_err(|_| "Couldn't write to stream!")?;

    {
        let mut buffer: [u8; 1] = [0];

        stream
            .read_exact(&mut buffer)
            .map_err(|_| "Couldn't read from stream!")?;

        if buffer[0] != 0 {
            return Err("Failure occured while listing directories!");
        }
    }

    for _ in 0..({
        let mut buffer: [u8; 4] = [0; 4];

        stream
            .read_exact(&mut buffer)
            .map_err(|_| "Couldn't read from stream!")?;

        u32::from_le_bytes(buffer)
    }) {
        let is_directory: bool = {
            let mut buffer: [u8; 1] = [0];

            stream
                .read_exact(&mut buffer)
                .map_err(|_| "Couldn't read from stream!")?;

            buffer[0] != 0
        };

        let name: String = read_string(&mut stream)?;

        console_write_line(format_args!(
            "[{}] {}",
            if is_directory { "DIR " } else { "FILE" },
            name
        ))?;
    }

    Ok(())
}
