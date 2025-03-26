use ctor::ctor;
use std::env;
use std::io::{self, BufRead, Write};
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const IPPROTO_ICMPV6: i32 = 58;
const ICMPV6_ECHO_REQUEST: u8 = 128;

fn get_client_ip() -> Option<String> {
    for var in ["SOCAT_PEERADDR", "TCPREMOTEIP", "REMOTE_ADDR"] {
        if let Ok(ip) = env::var(var) {
            if !ip.is_empty() {
                if ip.contains(":") {
                    return Some(ip);
                }
            }
        }
    }
    None
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn send_icmp_with_flag(dst_ip: &str, flag: &str) {
    let sock: RawFd = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_RAW, IPPROTO_ICMPV6)
    };

    if sock < 0 {
        eprintln!("socket failed: {}", io::Error::last_os_error());
        return;
    }

    let addr: Ipv6Addr = match dst_ip.trim().parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("Failed to parse IPv6 address: '{}'", dst_ip);
            unsafe { libc::close(sock) };
            return;
        }
    };

    let mut dst: libc::sockaddr_in6 = unsafe { MaybeUninit::zeroed().assume_init() };
    dst.sin6_family = libc::AF_INET6 as u16;
    dst.sin6_addr = unsafe { std::mem::transmute(addr.octets()) };

    let flag_bytes = flag.as_bytes();
    let flag_len = flag_bytes.len().min(1400);

    let pkt_len = 8 + flag_len;
    let mut pkt = vec![0u8; pkt_len];

    let pid = std::process::id() as u16;
    pkt[0] = ICMPV6_ECHO_REQUEST;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    pkt[4] = (pid >> 8) as u8;
    pkt[5] = (pid & 0xFF) as u8;
    pkt[6] = 0;
    pkt[7] = 1;

    pkt[8..8 + flag_len].copy_from_slice(&flag_bytes[..flag_len]);

    let sent = unsafe {
        libc::sendto(
            sock,
            pkt.as_ptr() as *const libc::c_void,
            pkt_len,
            0,
            &dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };

    if sent < 0 {
        eprintln!("sendto failed: {}", io::Error::last_os_error());
    }

    unsafe { libc::close(sock) };
}

static RUNNING: AtomicBool = AtomicBool::new(true);

#[ctor]
fn start_challenge() {
    thread::spawn(challenge_thread);
}

fn challenge_thread() {
    let client_ip = match get_client_ip() {
        Some(ip) => ip,
        None => {
            eprintln!("No client IP found in environment");
            return;
        }
    };

    let flag = match env::var("FLAG") {
        Ok(f) if !f.is_empty() => f,
        _ => {
            eprintln!("FLAG not set in environment");
            return;
        }
    };

    while RUNNING.load(Ordering::Relaxed) {
        send_icmp_with_flag(&client_ip, &flag);
        thread::sleep(Duration::from_secs(1));
    }
}

fn tris_print(board: &[[char; 3]; 3]) {
    println!("\n   1 2 3");
    for (r, row) in board.iter().enumerate() {
        print!("{}  ", (b'A' + r as u8) as char);
        for (c, &cell) in row.iter().enumerate() {
            let v = if cell == '\0' { '.' } else { cell };
            print!("{}", v);
            if c < 2 {
                print!(" ");
            }
        }
        println!();
    }
}

fn tris_check_winner(board: &[[char; 3]; 3]) -> i32 {
    const LINES: [[(usize, usize); 3]; 8] = [
        // rows
        [(0, 0), (0, 1), (0, 2)],
        [(1, 0), (1, 1), (1, 2)],
        [(2, 0), (2, 1), (2, 2)],
        // cols
        [(0, 0), (1, 0), (2, 0)],
        [(0, 1), (1, 1), (2, 1)],
        [(0, 2), (1, 2), (2, 2)],
        // diagonals
        [(0, 0), (1, 1), (2, 2)],
        [(0, 2), (1, 1), (2, 0)],
    ];

    for line in &LINES {
        let a = board[line[0].0][line[0].1];
        let b = board[line[1].0][line[1].1];
        let c = board[line[2].0][line[2].1];

        if a != '\0' && a == b && b == c {
            return if a == 'X' { 1 } else { 2 };
        }
    }
    0
}

fn tris_full(board: &[[char; 3]; 3]) -> bool {
    for row in board {
        for &cell in row {
            if cell == '\0' {
                return false;
            }
        }
    }
    true
}

fn tris_bot_move(board: &mut [[char; 3]; 3]) {
    let mut empties = Vec::new();
    for r in 0..3 {
        for c in 0..3 {
            if board[r][c] == '\0' {
                empties.push((r, c));
            }
        }
    }

    if empties.is_empty() {
        return;
    }

    let pick = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = now.as_nanos() as usize ^ std::process::id() as usize;
        seed % empties.len()
    };

    let (r, c) = empties[pick];
    board[r][c] = 'O';
}

fn main() {
    let mut board = [['\0'; 3]; 3];

    println!("Welcome in the mysterious game!");
    println!("Enter moves like A1, B3 etc. Or Q to quit.");

    let stdin = io::stdin();
    let mut turn = 0;

    loop {
        tris_print(&board);

        let winner = tris_check_winner(&board);
        if winner == 1 {
            println!("\nYou won!");
            break;
        }
        if winner == 2 {
            println!("\nYou lost. The bot won.");
            break;
        }
        if tris_full(&board) {
            println!("\nDraw: board full.");
            break;
        }

        if turn % 2 == 0 {
            print!("\nYour move (A1..C3, Q to quit): ");
            io::stdout().flush().unwrap();

            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) | Err(_) => {
                    println!("\nConnection closed.");
                    break;
                }
                Ok(_) => {}
            }

            let line = line.trim();

            if line.eq_ignore_ascii_case("q") {
                println!("Quitting.");
                break;
            }

            if line.len() < 2 {
                println!("Format not valid.");
                continue;
            }

            let chars: Vec<char> = line.chars().collect();
            let rch = chars[0].to_ascii_uppercase();
            let cch = chars[1];

            if !('A'..='C').contains(&rch) || !('1'..='3').contains(&cch) {
                println!("Format not valid.");
                continue;
            }

            let r = (rch as u8 - b'A') as usize;
            let c = (cch as u8 - b'1') as usize;

            if board[r][c] != '\0' {
                println!("Cell occupied, try again.");
                continue;
            }

            board[r][c] = 'X';
            turn += 1;
        } else {
            tris_bot_move(&mut board);
            println!("\nThe bot has moved.");
            turn += 1;
        }
    }

    println!("\nGame over.");
    RUNNING.store(false, Ordering::Relaxed);
}
