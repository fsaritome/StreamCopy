//! Test tool (only with `--features testtools`): a relay between a client and a receiver, to check the TLS binding
//! end to end. Plain mode forwards the encrypted bytes (like any router or proxy) — copies must work. `--terminate`
//! is a real man in the middle: it completes TLS with the client, opens its own TLS session to the receiver and
//! passes the decrypted bytes on — scopy must refuse, because the two sessions have different bindings.

use crate::tls;
use anyhow::Result;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

pub fn run(listen: u16, to: &str, terminate: bool) -> Result<()> {
    let l = TcpListener::bind(("0.0.0.0", listen))?;
    eprintln!("relay on :{listen} -> {to} ({})", if terminate { "terminating TLS: man in the middle" } else { "forwarding bytes" });
    for c in l.incoming() {
        let (c, to) = (c?, to.to_string());
        thread::spawn(move || {
            if let Err(e) = relay(c, &to, terminate) {
                eprintln!("relay: {e:#}");
            }
        });
    }
    Ok(())
}

fn relay(client: TcpStream, to: &str, terminate: bool) -> Result<()> {
    let up = TcpStream::connect(to)?;
    if !terminate {
        let (c2, u2) = (client.try_clone()?, up.try_clone()?);
        let a = thread::spawn(move || copy(c2, u2));
        copy(up, client);
        let _ = a.join();
        return Ok(());
    }
    // Short read timeouts so neither direction holds a TLS stream's lock while waiting (both directions share it).
    client.set_read_timeout(Some(Duration::from_millis(20)))?;
    up.set_read_timeout(Some(Duration::from_millis(20)))?;
    let (c, cb) = tls::accept(client)?;
    let (u, ub) = tls::connect(up)?;
    eprintln!("relay: client session {}…, receiver session {}…", &tls::hex(&cb)[..8], &tls::hex(&ub)[..8]);
    let (c2, u2) = (c.clone(), u.clone());
    let a = thread::spawn(move || copy(c2, u2));
    copy(u, c);
    let _ = a.join();
    Ok(())
}

/// Copies until EOF or error; read timeouts just mean "nothing yet".
fn copy(mut from: impl Read, mut to: impl Write) {
    let mut buf = vec![0u8; 256 << 10];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).and_then(|_| to.flush()).is_err() {
                    return;
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
            Err(_) => return,
        }
    }
}
