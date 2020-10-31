use anyhow::Context;
use nextcloud_passwords_client::{
    folder,
    password::{self, Password},
    service::{GeneratePassword, PasswordStrength},
    settings::{self, SETTINGS_NAMES, USER_SETTING_NAMES},
    AuthenticatedApi, LoginDetails, ResumeState,
};
use once_cell::unsync::OnceCell;
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::cell::Cell;
use structopt::StructOpt;
use uuid::Uuid;

mod crypto;
mod storage;

const RESUME_FILE: &str = "nextpass.json";
const PASSWORDS_FILE: &str = "nextpass_passwords.json";

fn print_password(password: &Password) {
    println!("{} [{}]", password.versioned.label, password.versioned.url);
    println!("   {}", password.versioned.username);
    println!("   {}", password.versioned.password);
    println!("--------------------")
}

pub struct LazyApi {
    api: OnceCell<AuthenticatedApi>,
    init: Cell<Option<LoginKind>>,
}

#[derive(Clone)]
pub enum LoginKind {
    Login(Option<std::path::PathBuf>),
    Resume(ResumeState),
}

impl LazyApi {
    pub fn into_inner(self) -> Option<AuthenticatedApi> {
        self.api.into_inner()
    }

    pub fn new(login: LoginKind) -> Self {
        Self {
            api: OnceCell::new(),
            init: Cell::new(Some(login)),
        }
    }

    async fn force_inner(
        this: &LazyApi,
        login: Option<LoginKind>,
    ) -> anyhow::Result<&AuthenticatedApi> {
        match login {
            None => (),
            Some(LoginKind::Login(login_details)) => {
                if let Err(_) = this.api.set(new_session(login_details).await?) {
                    panic!("Api was created twice");
                }
            }
            Some(LoginKind::Resume(resume_state)) => {
                if let Err(_) = this.api.set(
                    AuthenticatedApi::resume_session(resume_state)
                        .await
                        .with_context(|| "Could not resume the session")?
                        .0,
                ) {
                    panic!("Api was created twice")
                }
            }
        }
        Ok(this
            .api
            .get()
            .expect("cell was not initialized after force"))
    }

    pub async fn force(this: &LazyApi) -> anyhow::Result<&AuthenticatedApi> {
        let login = this.init.take();
        match Self::force_inner(this, login.clone()).await {
            Ok(api) => Ok(api),
            Err(e) => {
                this.init.set(login);
                Err(e)
            }
        }
    }

    pub async fn get(&self) -> anyhow::Result<&AuthenticatedApi> {
        Self::force(self).await
    }

    pub fn inner(&self) -> Option<&AuthenticatedApi> {
        self.api.get()
    }
}

#[derive(StructOpt)]
struct Args {
    #[structopt(
        long,
        short,
        help = "the login details if no previous login was attempted"
    )]
    login_details: Option<std::path::PathBuf>,
    #[structopt(long, default_value = "info")]
    log_level: LevelFilter,

    #[structopt(
        long,
        env = "NEXTPASS_KEY",
        hide_env_values = true,
        help = "passphrase to encrypt/decrypt the login informations to nextcloud"
    )]
    key: String,
    #[structopt(
        help = "If no subcommand is specified, search for a password with this pattern instead"
    )]
    pattern: Option<String>,
    #[structopt(subcommand)]
    sub_command: Option<Commands>,

    #[structopt(
        long,
        short,
        help = "do not save the state to disk (state is encrypted by the key) and don't load it"
    )]
    no_resume_state: bool,
}

#[derive(StructOpt)]
enum Commands {
    #[structopt(about = "fetch the passwords locally")]
    Fetch,
    #[structopt(about = "get the value of a setting")]
    GetSetting {
        #[structopt(possible_values = SETTINGS_NAMES)]
        name: settings::SettingVariant,
    },
    #[structopt(about = "print the values of all settings")]
    GetAllSettings,
    #[structopt(about = "set the value of a setting")]
    SetSetting {
        #[structopt(possible_values = USER_SETTING_NAMES)]
        name: settings::UserSettings,
        value: String,
    },
    #[structopt(about = "Create a password on the nextcloud instance")]
    Create {
        #[structopt(help = "The name of the password")]
        label: String,
        #[structopt(
            short,
            long,
            help = "actual password, if it is not specified it will be prompted on stdin",
            conflicts_with = "generate"
        )]
        password: Option<String>,
        #[structopt(short = "n", long, help = "the username for that password")]
        username: Option<String>,
        #[structopt(short, long, help = "the url that password is used on")]
        url: Option<String>,
        #[structopt(long, help = "additional (markdown compatible) notes")]
        notes: Option<String>,
        #[structopt(
            long,
            short,
            help = "instead of asking the password, generate it from the default settings"
        )]
        generate: bool,
        #[structopt(
            long,
            short,
            help = "If using --generate, add symbols",
            requires = "generate"
        )]
        symbols: bool,
        #[structopt(
            long,
            short = "d",
            help = "If using --generate, add numbers",
            requires = "generate"
        )]
        numbers: bool,
        #[structopt(
            long,
            short = "t",
            possible_values = &["1", "2", "3", "4"],
            parse(from_str = parse_strength),
            help = "If using --generate, the strength of the generated password",
            requires = "generate"
        )]
        strength: Option<PasswordStrength>,
    },
    #[structopt(
        about = "List all the passwords in a folder, if no folder is specified use the base folder"
    )]
    List { folder: Option<String> },
    #[structopt(about = "Generate a password")]
    Generate {
        #[structopt(possible_values = &["1", "2", "3", "4"], parse(from_str = parse_strength), default_value = "1", help = "The strength of the generated password")]
        strength: PasswordStrength,
        #[structopt(long, short, help = "Include symbols")]
        symbols: bool,
        #[structopt(long, short, help = "Include numbers")]
        numbers: bool,
    },
    #[structopt(about = "search for a password")]
    Search { pattern: String },
    #[structopt(about = "edit a password")]
    Edit {
        #[structopt(
            help = "pattern for the password to edit. If more than one are found, it will prompt a choice"
        )]
        pattern: String,
        #[structopt(short, long, help = "set the url")]
        url: Option<String>,
        #[structopt(short, long, help = "set the password, conflits with --prompt/-r")]
        password: Option<String>,
        #[structopt(
            short = "r",
            long = "prompt",
            help = "prompt the password",
            conflicts_with = "password"
        )]
        prompt_password: bool,
        #[structopt(short, long, help = "set the label")]
        label: Option<String>,
        #[structopt(short = "n", long, help = "set the username")]
        username: Option<String>,
    },
}

fn parse_strength(s: &str) -> PasswordStrength {
    match s {
        "1" => PasswordStrength::one(),
        "2" => PasswordStrength::two(),
        "3" => PasswordStrength::three(),
        "4" => PasswordStrength::four(),
        _ => unreachable!(),
    }
}

macro_rules! disp_or_not {
    (SharingTypes) => {
        "{:?}"
    };
    ($t:ident) => {
        "{}"
    };
}
macro_rules! print_setting_impl {
    ($variant_name:ident; $type:ty; $field_name:ident; $setting_string:expr => $s:expr) => {
        if let nextcloud_passwords_client::settings::SettingValue::$variant_name(value) = $s {
            println!(disp_or_not!($variant_name), value);
            return;
        }
    };
}
fn print_setting(setting: settings::SettingValue) {
    nextcloud_passwords_client::macro_on_settings!(print_setting_impl(setting));
}

fn print_folder(folder: folder::Folder) {
    if let Some(folders) = &folder.folders {
        println!("-- Folders --");
        for children in folders {
            println!("[FOLDER] {}", children.versioned.label);
        }
    }
    if let Some(passwords) = &folder.passwords {
        println!("-- Passwords --");
        for password in passwords {
            println!("[PASS] {}", password.versioned.label);
        }
    }
}

async fn new_session(
    login_detail_path: Option<impl AsRef<std::path::Path>>,
) -> anyhow::Result<AuthenticatedApi> {
    let login_details: LoginDetails = match login_detail_path {
        Some(login_detail_path) => {
            let login_details = std::fs::File::open(login_detail_path)
                .with_context(|| "Could not open login_details")?;
            serde_json::from_reader(login_details).with_context(|| "invalid login details")?
        }
        None => run_login_flow().await?,
    };

    let (api, session_id) = AuthenticatedApi::new_session(login_details)
        .await
        .with_context(|| "could not open a session")?;
    log::debug!("Started new session id {}", session_id);

    Ok(api)
}

async fn search_for_password(
    pattern: &str,
    api: &LazyApi,
    password_file: impl AsRef<std::path::Path>,
    key: &crypto::Key,
) -> anyhow::Result<()> {
    let passwords = storage::Passwords::open_or_fetch(password_file, key, api).await?;

    let mut result = passwords.query(pattern);
    if atty::is(atty::Stream::Stdout) {
        result.for_each(|p| print_password(&p));
    } else {
        if let Some(password) = result.next() {
            println!("{}", password.versioned.password);
        }
    }

    Ok(())
}

fn password_search(
    pattern: &str,
    passwords: impl IntoIterator<Item = Password>,
) -> impl Iterator<Item = Password> {
    let pattern = pattern.to_lowercase();

    passwords.into_iter().filter(move |password| {
        password.versioned.url.to_lowercase().contains(&pattern)
            || password.versioned.label.to_lowercase().contains(&pattern)
    })
}

async fn run_login_flow() -> anyhow::Result<LoginDetails> {
    println!("No login details detected, you must login first");
    let server: nextcloud_passwords_client::Url = promptly::prompt("Server url")?;

    LoginDetails::register_login_flow_2(server, |url| println!("Please login at: {}", url))
        .await
        .map_err(Into::into)
}

async fn edit_password(
    api: &LazyApi,
    pattern: &str,
    password: Option<String>,
    url: Option<String>,
    label: Option<String>,
    username: Option<String>,
) -> anyhow::Result<()> {
    let passwords = api.get().await?.password().list(None).await?;
    let selected: Vec<_> = password_search(pattern, passwords).collect();

    println!("Passwords: ");
    for (i, password) in selected.iter().enumerate() {
        println!("{} - {}", i + 1, password.versioned.label)
    }
    println!("0 to cancel");

    let choice: usize = promptly::prompt("Password to edit")?;
    if choice == 0 {
        return Ok(());
    }

    let choice = choice - 1;
    if choice > selected.len() {
        return Err(anyhow::anyhow!("Invalid password choice"));
    }

    // Take the choice-th element. This won't panic because we have done the bound checking
    let selected = selected.into_iter().nth(choice).unwrap();

    let password = password.unwrap_or(selected.versioned.password);
    let hash = crypto::hash_sha1(&password);

    let mut update_password = password::UpdatePassword::new(
        label.unwrap_or(selected.versioned.label),
        password,
        hash,
        selected.id,
    );
    update_password.url = url.or(Some(selected.versioned.url));
    update_password.username = username.or(Some(selected.versioned.username));

    api.get().await?.password().update(update_password).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    TermLogger::init(args.log_level, Config::default(), TerminalMode::Mixed)?;

    let key = crypto::hash_password(args.key)?;

    let api_login = if args.no_resume_state {
        LoginKind::Login(args.login_details)
    } else {
        let mut data_dir = dirs_next::data_dir().with_context(|| "no data dir available")?;
        data_dir.push(RESUME_FILE);
        if !data_dir.exists() {
            LoginKind::Login(args.login_details)
        } else {
            let resume_state: ResumeState = crypto::open(data_dir, &key)?;
            LoginKind::Resume(resume_state)
        }
    };
    let api = LazyApi::new(api_login);

    let mut passwords_file = dirs_next::data_dir().with_context(|| "no data dir available")?;
    passwords_file.push(PASSWORDS_FILE);

    match args.sub_command {
        Some(command) => match command {
            Commands::Fetch => {
                storage::Passwords::fetch(&api)
                    .await?
                    .store(&passwords_file, &key)?;
            }
            Commands::Edit {
                pattern,
                prompt_password,
                url,
                mut password,
                label,
                username,
            } => {
                if prompt_password {
                    password = Some(rpassword::read_password_from_tty(Some("Password: "))?);
                }
                edit_password(&api, &pattern, password, url, label, username).await?;
                storage::Passwords::fetch(&api)
                    .await?
                    .store(&passwords_file, &key)?;
            }
            Commands::GetSetting { name } => {
                let setting = api.get().await?.settings().get().from_variant(name).await?;
                print_setting(setting);
            }
            Commands::GetAllSettings => {
                let settings = api.get().await?.settings().get_all().await?;
                println!("{:#?}", settings)
            }
            Commands::SetSetting { name, value } => {
                let valued_setting = settings::UserSettingValue::from_variant(name, &value)?;
                let settings = settings::Settings::new().set_user_value(valued_setting);
                api.get().await?.settings().set(settings).await?;
            }
            Commands::Create {
                label,
                password,
                username,
                url,
                notes,
                generate,
                symbols,
                numbers,
                strength,
            } => {
                let password = match password {
                    Some(p) => p,
                    None if !generate => rpassword::read_password_from_tty(Some("Password: "))?,
                    None => {
                        let mut generate =
                            GeneratePassword::new().numbers(numbers).special(symbols);
                        if let Some(strength) = strength {
                            generate = generate.strength(strength);
                        }
                        let password = api
                            .get()
                            .await?
                            .service()
                            .generate_password(generate)
                            .await?
                            .password;
                        println!("Generated password: {}", password);
                        password
                    }
                };
                let hash = crypto::hash_sha1(&password);
                let mut request = password::CreatePassword::new(label, password, hash);
                request.username = username;
                request.url = url;
                request.notes = notes;
                api.get().await?.password().create(request).await?;

                storage::Passwords::fetch(&api)
                    .await?
                    .store(&passwords_file, &key)?;
            }
            Commands::List { folder } => {
                let folder = match folder {
                    None => {
                        api.get()
                            .await?
                            .folder()
                            .get(
                                Some(folder::Details::new().passwords().folders()),
                                Uuid::nil(),
                            )
                            .await?
                    }
                    Some(folder) => {
                        let folder = folder.to_lowercase();
                        api.get()
                            .await?
                            .folder()
                            .list(Some(folder::Details::new().passwords().folders()))
                            .await?
                            .into_iter()
                            .find(|f| f.versioned.label.to_lowercase().contains(&folder))
                            .ok_or(anyhow::anyhow!("Folder not found"))?
                    }
                };
                print_folder(folder);
            }
            Commands::Generate {
                strength,
                numbers,
                symbols,
            } => {
                let generate = GeneratePassword::new()
                    .strength(strength)
                    .numbers(numbers)
                    .special(symbols);
                let password = api
                    .get()
                    .await?
                    .service()
                    .generate_password(generate)
                    .await?;
                println!("{}", password.password);
            }
            Commands::Search { pattern } => {
                search_for_password(&pattern, &api, &passwords_file, &key).await?
            }
        },
        None => match args.pattern {
            None => Err(anyhow::anyhow!(
                "No command provided, must provide a pattern to search"
            ))?,
            Some(pattern) => search_for_password(&pattern, &api, &passwords_file, &key).await?,
        },
    }

    match api.inner() {
        Some(api) if !args.no_resume_state => {
            log::debug!("Saving state");
            let save_state = api.get_state();
            let mut data_dir = dirs_next::data_dir().with_context(|| "no data dir available")?;
            data_dir.push(RESUME_FILE);
            log::debug!("Using {} as resume path", data_dir.display());

            crypto::store(&save_state, data_dir, &key)?;
        }
        _ => (),
    }

    if let Some(api) = api.into_inner() {
        api.disconnect().await?;
    }

    Ok(())
}
