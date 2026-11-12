//! Installs or removes the virtual camera's media source. Run elevated.
//!
//! ```text
//! skakel-vcam-install install <path to skakel_vcam_source.dll>
//! skakel-vcam-install uninstall
//! skakel-vcam-install status
//! ```

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::path::Path;
    use std::process::ExitCode;

    use skakel_vcam::{Error, install, sys};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["install", dll] => install::install(Path::new(dll)).map(|done| {
            println!(
                "Installed version {} as {}",
                done.version,
                done.path.display()
            );
            for path in done.pending_delete {
                println!(
                    "Still in use, deleted at the next restart: {}",
                    path.display()
                );
            }
            for path in done.left_behind {
                println!(
                    "Older version left in place, delete it by hand: {}",
                    path.display()
                );
            }
        }),
        ["uninstall"] => install::uninstall().map(|pending| {
            println!("Uninstalled.");
            for path in pending {
                println!(
                    "Still in use, deleted at the next restart: {}",
                    path.display()
                );
            }
        }),
        ["status"] => sys::check_supported()
            .and_then(|()| install::registered_path())
            .map(|path| match path {
                Some(path) => println!("Registered: {}", path.display()),
                None => println!("Not installed."),
            }),
        _ => {
            eprintln!(
                "usage: skakel-vcam-install install <skakel_vcam_source.dll> | uninstall | status"
            );
            return ExitCode::from(64);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Windows 10 is not a failure of the installer: the camera does not exist there.
        Err(Error::Unsupported(why)) => {
            println!("The virtual camera is not supported here: {why}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The virtual camera is Windows only.");
}
