use std::{
    env,
    error::Error,
    ffi::CString,
    fs::{self, File, Permissions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    process::exit,
};

use flate2::read::GzDecoder;

use tar::Archive;

fn main() {
    #![allow(unused_must_use)]
    main_with_error().is_err_and(|err| {
        eprintln!("fatal: {err}");
        exit(1);
    });
}

fn main_with_error() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;

    if args.context_dir.exists() {
        if !args.use_existing_dir {
            Err(format!(
                "output directory already exists ('{p}')",
                p = args.context_dir.display()
            ))?
        }
    } else {
        fs::create_dir(&args.context_dir)
            .map_err(|err| format!("failed to create output directory - {err}"))?;

        fs::set_permissions(&args.context_dir, Permissions::from_mode(0o700))
            .map_err(|err| format!("failed to chmod output directory - {err}"))?;
    }

    let output_dir = File::open(&args.context_dir).map_err(|err| {
        format!(
            "failed to open output directory {} - {}",
            args.context_dir.display(),
            err
        )
    })?;

    enter_sandbox(args.context_dir.as_path())
        .map_err(|err| format!("failed to enter sandbox - {err}"))?;

    // The following awful code abstracts different tar types.
    // It is based on this stackoverflow answer by Emoun and
    // Chayim Friedman respectively:
    // - https://stackoverflow.com/a/67041779
    // - https://stackoverflow.com/a/70104523
    //
    // Part 1/2:
    //   These two variables satisfy the borrow checker and avoid
    //   dropping references to the underlying values. They also
    //   tell the compiler the size of the underlying data:
    let (mut gz, mut stdin);

    // Part 2/2:
    //   Lastly, to satisfy the Read trait required by the Archive
    //   library, we need a mutable reference to the underlying
    //   values. First, we set the concrete variables to their
    //   respective values. Then, we take a mutable reference
    //   to those variables:
    let reader: &mut dyn Read = if args.gzip {
        gz = GzDecoder::new(io::stdin());
        &mut gz
    } else {
        stdin = io::stdin();
        &mut stdin
    };

    let mut archive = Archive::new(reader);

    for entry_result in archive.entries()? {
        let mut entry = entry_result.map_err(|err| format!("failed to get tar entry - {err}"))?;

        let path = entry
            .path()
            .map_err(|err| format!("failed to get entry's path - {err}"))?;

        let mode = entry.header().mode().map_err(|err| {
            format!(
                "failed to get file mode for entry {} - {}",
                path.display(),
                err
            )
        })?;

        let perm = Permissions::from_mode(mode);

        match args.verbose {
            0 => {}
            1 => eprintln!("{d}", d = path.display()),
            _ => eprintln!(
                "{path} | 0x{type_b:x} | 0o{mode:o}",
                path = path.display(),
                type_b = entry.header().entry_type().as_byte(),
                mode = mode,
            ),
        }

        if entry.header().entry_type().is_dir() {
            if args.use_existing_dir {
                let exists = existsat(&output_dir, path.as_ref())
                    .map_err(|err| format!("failed to existsat {} - {}", path.display(), err))?;
                if exists {
                    continue;
                }
            }

            mkdirat(&output_dir, path.as_ref(), perm).map_err(|err| {
                format!("failed to mkdirat for entry {} - {}", path.display(), err)
            })?;

            continue;
        }

        if args.use_existing_dir {
            unlinkat_if_exists(&output_dir, path.as_ref())
                .map_err(|err| format!("failed to unlinkat {} - {}", path.display(), err))?;
        }

        let mut current_file = openat(
            &output_dir,
            path.as_ref(),
            libc::O_CREAT | libc::O_WRONLY,
            perm,
        )
        .map_err(|err| format!("failed to openat entry {} = {}", path.display(), err))?;

        // We need a separate variable for the file path because the tar
        // entry's ownership is transferred to io::copy, which makes it
        // unavailable to map_err. We do this here rather than at the
        // start of the function because ownership only becomes
        // problematic here.
        //
        // No idea what the performance penalty / overhead of this is,
        // but I think it is important to have useful error messages.
        // Re-running with "-v" is not really useful for transient
        // failures.
        let err_path = PathBuf::from(path.as_ref());

        io::copy(&mut entry, &mut current_file).map_err(|err| {
            format!(
                "failed to write entry to file system {} - {}",
                err_path.display(),
                err
            )
        })?;
    }

    Ok(())
}

struct Args {
    use_existing_dir: bool,
    gzip: bool,
    verbose: u8,
    context_dir: PathBuf,
}

const USAGE: &str = "SYNOPSIS
  sbtar [options] < /path/to/file.tar

DESCRIPTION
  sbtar enters a sandbox and extracts a tar from standard input
  into a directory.

OPTIONS
  -C <dir>    Switch to directory 'dir' before creation or extraction
  -F          Allow extracting into an existing directory
  -h, --help  Display this information
  -z, --gzip  File is gzip-compressed
  -v[v]       Enable verbose logging
  --version   Write the version number to stdout and exit";

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args {
        use_existing_dir: false,
        gzip: false,
        verbose: 0,
        context_dir: PathBuf::from("."),
    };

    let mut parser = argparse::ArgumentParser::new();

    parser.add_option(&["-h", "--help"], Help {}, "Display this information");

    parser.refer(&mut args.context_dir).add_option(
        &["-C"],
        argparse::Parse,
        "Switch to directory 'dir' before creation or extraction",
    );

    parser.refer(&mut args.use_existing_dir).add_option(
        &["-F"],
        argparse::StoreTrue,
        "Allow extracting into an existing directory",
    );

    parser.refer(&mut args.gzip).add_option(
        &["-z", "--gzip"],
        argparse::StoreTrue,
        "File is gzip-compressed",
    );

    parser.add_option(
        &["--version"],
        argparse::Print(env!("CARGO_PKG_VERSION").to_string()),
        "Write the version number to stdout and exit",
    );

    parser.refer(&mut args.verbose).add_option(
        &["-v"],
        argparse::IncrBy(1),
        "Enable verbose logging",
    );

    parser.parse_args_or_exit();

    drop(parser);

    to_abs_path(&mut args.context_dir)
        .map_err(|err| format!("failed to get absolute path for context directory - {err}"))?;

    Ok(args)
}

struct Help {}

impl argparse::action::IFlagAction for Help {
    fn parse_flag(&self) -> argparse::action::ParseResult {
        eprintln!("{USAGE}");
        exit(1);
    }
}

// Some sandboxing code (like that of macOS) requires
// paths be absolute.
fn to_abs_path(path_buf: &mut PathBuf) -> Result<(), Box<dyn Error>> {
    if path_buf.is_relative() {
        // TODO: Use std::path::absolute when comfi with going
        // to rust version >=1.79:
        // https://doc.rust-lang.org/std/path/fn.absolute.html
        //
        // The problem with fs::canonicalize is that it needs to
        // access the file system, thus a nonexistent path will
        // result in an error. The following "match" expression
        // attempts to awkwardly deal with that.
        match fs::canonicalize(path_buf.clone()) {
            Ok(p) => {
                path_buf.clear();
                path_buf.push(p);
            }
            Err(_) => {
                let cwd = env::current_dir()
                    .map_err(|err| format!("failed to get current working directory - {err}"))?;

                let path_clone = path_buf.clone();

                path_buf.clear();

                path_buf.push(cwd);

                path_buf.push(path_clone);
            }
        };
    }

    Ok(())
}

#[cfg(target_os = "freebsd")]
fn enter_sandbox(_: &Path) -> Result<(), Box<dyn Error>> {
    if unsafe { libc::cap_enter() } != 0 {
        Err(last_error("cap_enter failed"))?;
    }

    Ok(())
}

#[cfg(target_os = "openbsd")]
fn enter_sandbox(output_dir: &Path) -> Result<(), Box<dyn Error>> {
    let path_cstring = path_to_cstring(output_dir)?;
    let unveil_perms = CString::new("rwc")?;

    if unsafe { libc::unveil(path_cstring.as_ptr(), unveil_perms.as_ptr()) } != 0 {
        Err(last_error("unveil failed"))?;
    }

    if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } != 0 {
        Err(last_error("unveil lock failed"))?;
    }

    let promises = CString::new("stdio rpath wpath cpath fattr")?;
    let exec_promises = CString::new("")?;

    if unsafe { libc::pledge(promises.as_ptr(), exec_promises.as_ptr()) } != 0 {
        Err(last_error("pledge failed"))?;
    }

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn enter_sandbox(output_dir: &Path) -> Result<(), Box<dyn Error>> {
    let profile = CString::new(format!(
        "(version 1)
(deny default)
(allow file-read* file-write*
    (subpath \"{}\"))",
        output_dir.display()
    ))?;

    // Double pointer by troop357.
    // Note: Instead of creating a second variable like troop357 does,
    // we can create the parent pointer in the function call's ():
    // https://stackoverflow.com/a/58530805
    let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();

    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut errorbuf) };
    if result != 0 {
        match unsafe { CString::from_raw(errorbuf) }.into_string() {
            Ok(msg) => Err(format!("sandbox init failed - {}", msg))?,
            Err(err) => Err(format!(
                "sandbox init failed - unknown error (failed to convert errorbuf to string: {err})"
            ))?,
        }
    }

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[link(name = "sandbox")]
extern "C" {
    /// Refer to: /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sandbox.h
    ///
    /// For an example with sandbox_init_with_parameters, refer to:
    /// https://github.com/chromium/chromium/blob/780128faaadb425a15144678b5591a85d19aa891/sandbox/mac/seatbelt_sandbox_design.md#appendix
    ///
    /// From the sandbox.h:
    ///
    /// @function sandbox_init
    /// Places the current process in a sandbox with a profile as
    /// specified.  If the process is already in a sandbox, the new profile
    /// is ignored and sandbox_init() returns an error.
    ///
    /// @param profile (input)   The Sandbox profile to be used.  The format
    /// and meaning of this parameter is modified by the `flags' parameter.
    ///
    /// @param flags (input)   Must be SANDBOX_NAMED.  All other
    /// values are reserved.
    ///
    /// @param errorbuf (output)   In the event of an error, sandbox_init
    /// will set `*errorbuf' to a pointer to a NUL-terminated string
    /// describing the error. This string may contain embedded newlines.
    /// This error information is suitable for developers and is not
    /// intended for end users.
    ///
    /// If there are no errors, `*errorbuf' will be set to NULL.  The
    /// buffer `*errorbuf' should be deallocated with `sandbox_free_error'.
    ///
    /// @result 0 on success, -1 otherwise.
    ///
    /// int sandbox_init(
    ///   const char *profile,
    ///   uint64_t flags,
    ///   char **errorbuf);
    fn sandbox_init(
        profile: *const std::ffi::c_char,
        flags: u64,
        errorbuf: *mut *mut std::ffi::c_char,
    ) -> i32;
}

fn mkdirat(dir: &File, p: &Path, perm: Permissions) -> Result<(), Box<dyn Error>> {
    let path_cstring = path_to_cstring(p)?;

    let mode = permissions_to_mode(perm)?;

    let res = unsafe { libc::mkdirat(dir.as_raw_fd(), path_cstring.as_ptr(), mode) };
    if res != 0 {
        Err(last_error("mkdirat failed"))?
    }

    Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
fn permissions_to_mode(perm: Permissions) -> Result<u16, Box<dyn Error>> {
    let mode = u16::try_from(perm.mode())?;
    Ok(mode)
}

#[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "ios")))]
fn permissions_to_mode(perm: Permissions) -> Result<u32, Box<dyn Error>> {
    Ok(perm.mode())
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
