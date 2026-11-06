//! Running the receiver as a systemd service on Linux (`scopy service install|uninstall`), the counterpart of
//! service.rs on Windows. The unit runs `scopy serve <args>` as root from where the binary is now (install from
//! where it stays, e.g. /usr/local/bin/scopy); systemd keeps the job records (`StateDirectory`, /var/lib/scopy,
//! 0700) and the token socket's folder (`RuntimeDirectory`, /run/scopy). Log lines go to the journal
//! (`journalctl -u scopy`).

use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

const NAME: &str = "scopy.service";
const UNIT_PATH: &str = "/etc/systemd/system/scopy.service";

/// systemd's command-line quoting: each word in double quotes, `\` and `"` escaped, `%` doubled (specifiers), `$`
/// doubled (environment expansion).
fn quote(word: &str) -> String {
    let mut s = String::from("\"");
    for c in word.chars() {
        match c {
            '\\' | '"' => {
                s.push('\\');
                s.push(c);
            }
            '%' => s.push_str("%%"),
            '$' => s.push_str("$$"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

fn unit_text(exe: &str, serve_args: &[String]) -> String {
    let mut cmd = vec![quote(exe), "serve".to_string()];
    cmd.extend(serve_args.iter().map(|a| quote(a)));
    format!(
        "# Written by `scopy service install`; `scopy service uninstall` removes it.\n\
         [Unit]\n\
         Description=StreamCopy receiver (scopy)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         StateDirectory=scopy\n\
         StateDirectoryMode=0700\n\
         RuntimeDirectory=scopy\n\
         RuntimeDirectoryMode=0755\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        cmd.join(" ")
    )
}

fn systemctl(args: &[&str]) -> Result<()> {
    let st = Command::new("systemctl").args(args).status().context("cannot run systemctl (is this a systemd system?)")?;
    if !st.success() {
        bail!("systemctl {} failed ({st})", args.join(" "));
    }
    Ok(())
}

fn need_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("installing the service needs root (sudo scopy service ...)");
    }
    Ok(())
}

/// Writes the unit, enables it and (re)starts it.
pub fn install(serve_args: Vec<OsString>) -> Result<()> {
    need_root()?;
    let exe = std::env::current_exe()?;
    let exe = exe.to_str().context("the path of the scopy binary is not UTF-8")?.to_string();
    if exe.starts_with("/home/") || exe.starts_with("/tmp/") {
        eprintln!("note: the service runs {exe}; install from where scopy stays (e.g. /usr/local/bin/scopy)");
    }
    let args: Vec<String> = serve_args
        .iter()
        .map(|a| a.to_str().map(str::to_string).context("a service argument is not UTF-8"))
        .collect::<Result<_>>()?;
    let text = unit_text(&exe, &args);
    let tmp = format!("{UNIT_PATH}.new");
    std::fs::write(&tmp, text).with_context(|| format!("cannot write {tmp}"))?;
    std::fs::rename(&tmp, UNIT_PATH).with_context(|| format!("cannot write {UNIT_PATH}"))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", NAME])?;
    systemctl(&["restart", NAME])?;
    println!("installed and started {NAME} ({UNIT_PATH}); log: journalctl -u scopy");
    Ok(())
}

/// Stops and disables the service and removes the unit. Job records in /var/lib/scopy stay.
pub fn uninstall() -> Result<()> {
    need_root()?;
    if !Path::new(UNIT_PATH).exists() {
        bail!("{UNIT_PATH} does not exist (not installed by scopy)");
    }
    systemctl(&["disable", "--now", NAME])?;
    std::fs::remove_file(UNIT_PATH).with_context(|| format!("cannot remove {UNIT_PATH}"))?;
    systemctl(&["daemon-reload"])?;
    println!("stopped and removed {NAME}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_quotes_every_word() {
        assert_eq!(quote(r#"a "b" \c 50% $HOME"#), r#""a \"b\" \\c 50%% $$HOME""#);
        let u = unit_text("/usr/local/bin/scopy", &["--share".into(), "data=/data/my share".into()]);
        assert!(u.contains("ExecStart=\"/usr/local/bin/scopy\" serve \"--share\" \"data=/data/my share\"\n"));
        assert!(u.contains("StateDirectory=scopy\n") && u.contains("WantedBy=multi-user.target\n"));
    }
}
