# sbtar

sbtar enters a sandbox and extracts a tar from standard input
into a directory.

Please note that this project is experimental. I developed it
to learn about Rust and its foreign function interface. It is
not meant as a full `tar` replacement.

## Features

- Leverages various operating systems' sandboxing features to prevent
  path traversal or other security sadness when extracting a tar file
  (refer to the [Supported systems section](#supported-systems) for
  details)
- Supports gzip-compressed tar files
- Defaults to not allowing extraction into an existing directory
  (this behavior can be overridden with an argument)
- Somewhat close adherence to bsdtar's CLI

## Supported systems

sbtar supports the following operating systems:

- FreeBSD (uses [capsicum][capsicum])
- OpenBSD (uses [pledge][pledge] and [unveil][unveil])
- macOS (uses [sandbox.framework / seatbelt][sandbox-framework])

[capsicum]: https://man.freebsd.org/cgi/man.cgi?capsicum(4)
[pledge]: https://man.openbsd.org/pledge.2
[unveil]: https://man.openbsd.org/unveil.2
[sandbox-framework]: https://github.com/chromium/chromium/blob/780128faaadb425a15144678b5591a85d19aa891/sandbox/mac/seatbelt_sandbox_design.md#appendix

## Installation

The following dependencies are required to install sbtar:

- git
- rust (cargo)

To install without cloning the source code:

```sh
cargo install --git https://gitlab.com/stephen-fox/sbtar
```

Alternatively, install from a copy of the source code:

```sh
git clone https://gitlab.com/stephen-fox/sbtar
cd sbtar
cargo install --path .
```

## Usage

```
sbtar [options] < /path/to/file.tar

OPTIONS
  -C <dir>    Switch to directory 'dir' before creation or extraction
  -F          Allow extracting into an existing directory (i.e., allow
              files to be overwritten in an existing directory)
  -h, --help  Display this information
  -z, --gzip  File is gzip-compressed
  -v[v]       Enable verbose logging
  --version   Write the version number to stdout and exit
```

## Examples

```sh
# Extract a standard tar file into a directory named "foo":
sbtar -C foo < file.tar

# Extract a gzip-compressed tar:
sbtar -z -C foo < file.tar.gz

# Extract into an existing directory:
sbtar -F -C foo < file.tar

# Enable verbose logging:
sbtar -v -C foo < file.tar
```
