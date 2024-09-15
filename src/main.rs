use std::{
    env,
    error::Error,
    fs::{self, Permissions},
    io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::exit,
};

use cap_std::fs::{
    Dir as CapDir, DirBuilder as CapDirBuilder, DirBuilderExt as CapDirBuilderExt,
    Permissions as CapPermissions, PermissionsExt as CapPermissionsExt,
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

    let output = CapDir::open_ambient_dir(&args.output_dir, cap_std::ambient_authority())?;

    capsicum::enter()?;

    let mut archive = Archive::new(GzDecoder::new(io::stdin()));

    let mut output_builder = CapDirBuilder::new();
    output_builder.recursive(true);

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;

        let current_path = entry.path()?;

        if args.verbose {
            eprintln!("{d}", d = current_path.display());
        }

        let current_mode = entry.header().mode()?;

        let mut file_path = PathBuf::new();
        file_path.push(&current_path);

        if entry.header().entry_type().is_dir() {
            output_builder.mode(current_mode);

            CapDir::create_dir_with(&output, file_path.as_path(), &output_builder)?;

            continue;
        }

        let mut current_file = output.create(file_path)?;

        current_file.set_permissions(CapPermissions::from_mode(current_mode))?;

        io::copy(&mut entry, &mut current_file)?;
    }

    Ok(())
}

struct Args {
    use_existing_dir: bool,
    verbose: bool,
    output_dir: PathBuf,
}

const USAGE: &str = "ctgz

SYNOPSIS
  ctgz [options] OUTPUT-DIR

DESCRIPTION
  ctgz extracts a tar.gz from stdin into OUTPUT-DIR in capsicum mode.

OPTIONS
  -F            Allow extracting into an existing directory
  -h, --help    Display this information
  -v, --verbose Enable verbose logging";

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut args = Args {
        use_existing_dir: false,
        verbose: false,
        output_dir: PathBuf::new(),
    };

    for (i, arg) in env::args().skip(1).enumerate() {
        match arg.as_str() {
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                exit(1);
            }
            "-F" => args.use_existing_dir = true,
            "-v" | "--verbose" => args.verbose = true,
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
