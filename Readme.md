# nextpass
---

A CLI to Nextcloud Passwords

The CLI will prompt you with the server you want to use if you do not provide a `LoginDetails` file. Check the `nextcloud-passwords-client` documentation if you want to supply your own.

Those details are safely encrypted with the `key` argument, or the `NEXTPASS_KEY` variable.

The cli will also detect when you call it outside a tty, and it will only print the first found password in that case

## Installation

### AUR

There is a package availaible on the AUR: https://aur.archlinux.org/packages/nextpass/

### From Source

If you want to build the package from source you will need the Rust compiler, you can get that from [rustup](https://rustup.rs/) for example. More information on installing Rust can be found [here](https://www.rust-lang.org/tools/install).
A minimum of 1.39 is required to compile this program.

Once you have a rust compiler, you can run `cargo build --release` and it will output the binary at `./target/release/nextpass`
