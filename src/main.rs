use std::{
    env,
    error::Error,
    ffi::CString,
    fs::{self, File, Permissions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    process::exit,
};

use flate2::read::GzDecoder;

use tar::Archive;

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    if args.output_dir.exists() {
        if !args.use_existing_dir {
            Err(format!(
                "output directory already exists ('{p}')",
                p = args.output_dir.display()
            ))?
        }
    } else {
        fs::create_dir(&args.output_dir)?;
        fs::set_permissions(&args.output_dir, Permissions::from_mode(0o700))?;
    }

    let output_dir = File::open(args.output_dir)?;

    let enter_res = unsafe { libc::cap_enter() };
    if enter_res != 0 {
        Err(last_error("cap_enter failed"))?;
    }

    let mut archive = Archive::new(GzDecoder::new(io::stdin()));

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;

        let current_path = entry.path()?;
        let current_mode = entry.header().mode()?;
        let current_perm = Permissions::from_mode(current_mode);

        match args.verbose {
            0 => {}
            1 => eprintln!("{d}", d = current_path.display()),
            _ => eprintln!(
                "{d} | 0o{m:o}",
                d = current_path.display(),
                m = current_mode,
            ),
        }

        if entry.header().entry_type().is_dir() {
            mkdirat(&output_dir, current_path.as_ref(), current_perm)?;

            continue;
        }

        let mut current_file = openat(&output_dir, current_path.as_ref(), current_perm)?;

        io::copy(&mut entry, &mut current_file)?;
    }

    Ok(())
}

struct Args {
    use_existing_dir: bool,
    verbose: u8,
    output_dir: PathBuf,
}

const USAGE: &str = "ctgz

SYNOPSIS
  ctgz [options] OUTPUT-DIR

DESCRIPTION
  ctgz extracts a tar.gz from stdin into OUTPUT-DIR in capsicum mode.

OPTIONS
  -F          Allow extracting into an existing directory
  -h, --help  Display this information
  -v[v]       Enable verbose logging";

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args {
        use_existing_dir: false,
        verbose: 0,
        output_dir: PathBuf::new(),
    };

    for (i, arg) in env::args().skip(1).enumerate() {
        match arg.as_str() {
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                exit(1);
            }
            "-F" => args.use_existing_dir = true,
            "-v" => args.verbose = args.verbose + 1,
            "-vv" => args.verbose = args.verbose + 2,
            _ => {
                if i == env::args().count() - 2 && !arg.starts_with("-") {
                    args.output_dir.push(arg);
                    break;
                }

                Err(format!("unknown argument: {arg}"))?
            }
        }
    }

    if args.output_dir.display().to_string() == "" {
        Err("please specify an output directory as the final argument")?
    }

    Ok(args)
}

fn mkdirat(dir: &File, p: &Path, perm: Permissions) -> Result<(), Box<dyn Error>> {
    let dir_fd = dir.as_raw_fd();

    let tmp = match p.to_str() {
        Some(s) => s,
        None => Err("path does not contain a string")?,
    };

    let tmp = CString::new(tmp)?;

    let mode = match u16::try_from(perm.mode()) {
        Ok(v) => v,
        Err(err) => Err(err)?,
    };

    let res = unsafe { libc::mkdirat(dir_fd, tmp.as_ptr(), mode) };
    if res != 0 {
        Err(last_error("mkdirat failed"))?
    }

    Ok(())
}

fn openat(dir: &File, p: &Path, perm: Permissions) -> Result<File, Box<dyn Error>> {
    let dir_fd = dir.as_raw_fd();

    let tmp = match p.to_str() {
        Some(s) => s,
        None => Err("path does not contain a string")?,
    };

    let tmp = CString::new(tmp)?;

    let res = unsafe { libc::openat(dir_fd, tmp.as_ptr(), libc::O_CREAT | libc::O_WRONLY) };
    if res < 0 {
        Err(last_error("openat failed"))?
    }

    let file = unsafe { File::from_raw_fd(res) };

    file.set_permissions(perm)?;

    Ok(file)
}

fn last_error(prefix: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{prefix} - {err}", err = std::io::Error::last_os_error()),
    )
}
