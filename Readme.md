# nextpass
---

A CLI to Nextcloud Passwords

The CLI will prompt you with the server you want to use if you do not provide a `LoginDetails` file. Check the `nextcloud-passwords-client` documentation if you want to supply your own.

Those details are safely encrypted with the `key` argument, or the `NEXTPASS_KEY` variable.

## Installation

### AUR

There is a package availaible on the AUR: https://aur.archlinux.org/packages/nextpass/

### From Source

If you want to build the package from source you will need the Rust compiler, you can get that from [rustup](https://rustup.rs/) for example. More information on installing Rust can be found [here](https://www.rust-lang.org/tools/install).

Once you have a rust compiler, you can run `cargo build --release` and it will output the binary at `./target/release/nextpass`
