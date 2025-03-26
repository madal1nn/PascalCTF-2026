use serde::Deserialize;
use std::io::{self, BufRead};

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Shrimppy {
    l0v3_: String,
    shr1mp5: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Shrimp {
    w3_: bool,
    shrimppy: Shrimppy,
    s34f00d: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Prawnn {
    pascal: String,
    CTF: u64,
    shrimp: Shrimp,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Lobstah {
    g0t_: String,
    l0bst3rd: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Lobster {
    y0u_: bool,
    lobstah: Lobstah,
    cl4ws: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Claww {
    pascal: String,
    CTF: u64,
    lobster: Lobster,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Oceann {
    s34_: String,
    d1v3r: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Ocean {
    d33p_: bool,
    oceann: Oceann,
    w4v35: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Abysss {
    pascal: String,
    CTF: u64,
    ocean: Ocean,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Shelll {
    c0d3_: String,
    ftw: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Shell {
    sh3ll_: bool,
    shelll: Shelll,
    b4sh: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Termm {
    pascal: String,
    CTF: u64,
    shell: Shell,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Rustyy {
    sup3r_: String,
    s4f3: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Rusty {
    ru5t_: bool,
    rustyy: Rustyy,
    m3m0ry: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Ferriss {
    pascal: String,
    CTF: u64,
    rusty: Rusty,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Crabby {
    l0v3_: Vec<String>,
    r3vv1ng_: u64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Crab {
    I_: bool,
    crabby: Crabby,
    cr4bs: i64,
}

#[allow(non_snake_case, dead_code)]
#[derive(Deserialize)]
struct Top {
    pascal: String,
    CTF: u64,
    crab: Crab,
}

#[inline(never)]
fn parse<T: for<'de> Deserialize<'de>>(s: &str) -> Option<T> {
    std::hint::black_box(serde_json::from_str(s).ok())
}

fn main() {
    println!("Give me a JSONy flag!");

    let stdin = io::stdin();
    let line = stdin.lock().lines().next().unwrap().unwrap();

    std::hint::black_box(parse::<Prawnn>(&line));
    std::hint::black_box(parse::<Claww>(&line));
    std::hint::black_box(parse::<Abysss>(&line));
    std::hint::black_box(parse::<Termm>(&line));
    std::hint::black_box(parse::<Ferriss>(&line));

    match serde_json::from_str::<Top>(&line) {
        Ok(_) => println!("🦀"),
        Err(e) => eprintln!("😔"),
    }
}
