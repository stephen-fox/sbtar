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
                "{path} | 0x{type_b:x} | 0o{mode:o}",
                path = current_path.display(),
                type_b = entry.header().entry_type().as_byte(),
                mode = current_mode,
            ),
        }

        if entry.header().entry_type().is_dir() {
            if args.use_existing_dir {
                let exists = existsat(&output_dir, current_path.as_ref())?;
                if exists {
                    continue;
                }
            }

            mkdirat(&output_dir, current_path.as_ref(), current_perm)?;

            continue;
        }

        if args.use_existing_dir {
            unlinkat_if_exists(&output_dir, current_path.as_ref())?;
        }

        let mut current_file = openat(
            &output_dir,
            current_path.as_ref(),
            libc::O_CREAT | libc::O_WRONLY,
            current_perm,
        )?;

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
    let path_cstring = path_to_cstring(p)?;

    let mode = match u16::try_from(perm.mode()) {
        Ok(v) => v,
        Err(err) => Err(err)?,
    };

    let res = unsafe { libc::mkdirat(dir.as_raw_fd(), path_cstring.as_ptr(), mode) };
    if res != 0 {
        Err(last_error("mkdirat failed"))?
    }

    Ok(())
}

fn openat(dir: &File, p: &Path, flags: i32, perm: Permissions) -> Result<File, Box<dyn Error>> {
    let path_cstring = path_to_cstring(p)?;

    let res = unsafe { libc::openat(dir.as_raw_fd(), path_cstring.as_ptr(), flags) };
    if res < 0 {
        Err(last_error("openat failed"))?
    }

    let file = unsafe { File::from_raw_fd(res) };

    file.set_permissions(perm)?;

    Ok(file)
}

fn existsat(dir: &File, p: &Path) -> Result<bool, Box<dyn Error>> {
    let path_cstring = path_to_cstring(p)?;

    let res = unsafe { libc::faccessat(dir.as_raw_fd(), path_cstring.as_ptr(), libc::F_OK, 0) };

    Ok(res == 0)
}

fn unlinkat_if_exists(dir: &File, p: &Path) -> Result<(), Box<dyn Error>> {
    let path_cstring = path_to_cstring(p)?;

    let res = unsafe { libc::faccessat(dir.as_raw_fd(), path_cstring.as_ptr(), libc::F_OK, 0) };
    if res != 0 {
        return Ok(());
    }

    let res = unsafe { libc::unlinkat(dir.as_raw_fd(), path_cstring.as_ptr(), 0) };
    if res != 0 {
        Err(last_error("unlinkat failed"))?;
    }

    Ok(())
}

fn path_to_cstring(p: &Path) -> Result<CString, Box<dyn Error>> {
    let path_cstring = match p.to_str() {
        Some(s) => s,
        None => Err("path does not contain a string")?,
    };

    let tmp = CString::new(path_cstring)?;

    Ok(tmp)
}

fn last_error(prefix: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{prefix} - {err}", err = std::io::Error::last_os_error()),
    )
}
