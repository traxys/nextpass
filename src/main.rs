use anyhow::Context;
use nextcloud_passwords_client::{
    folder,
    password::{self, Password},
    service::{GeneratePassword, PasswordStrength},
    settings::{self, SETTINGS_NAMES, USER_SETTING_NAMES},
    AuthenticatedApi, LoginDetails, ResumeState,
};
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use uuid::Uuid;

mod crypto;

const RESUME_FILE: &str = "nextpass.json";

fn print_password(password: &Password) {
    println!("{} [{}]", password.versioned.label, password.versioned.url);
    println!("   {}", password.versioned.username);
    println!("   {}", password.versioned.password);
    println!("--------------------")
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

async fn search_for_password(pattern: &str, api: &AuthenticatedApi) -> anyhow::Result<()> {
    let pattern = pattern.to_lowercase();

    let passwords = api.password().list(None).await?;
    passwords
        .iter()
        .filter(|password| {
            password.versioned.url.to_lowercase().contains(&pattern)
                || password.versioned.label.to_lowercase().contains(&pattern)
        })
        .for_each(print_password);
    Ok(())
}

async fn run_login_flow() -> anyhow::Result<LoginDetails> {
    println!("No login details detected, you must login first");
    let server: nextcloud_passwords_client::Url = promptly::prompt("Server url")?;

    LoginDetails::register_login_flow_2(server, |url| println!("Please login at: {}", url))
        .await
        .map_err(Into::into)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    TermLogger::init(args.log_level, Config::default(), TerminalMode::Mixed)?;

    let key = crypto::hash_password(args.key)?;

    let api = if args.no_resume_state {
        new_session(args.login_details).await?
    } else {
        let mut data_dir = dirs_next::data_dir().with_context(|| "no data dir available")?;
        data_dir.push(RESUME_FILE);
        if !data_dir.exists() {
            new_session(args.login_details).await?
        } else {
            let resume_state: ResumeState = crypto::open(data_dir, &key)?;
            AuthenticatedApi::resume_session(resume_state)
                .await
                .with_context(|| "Could not resume the session")?
                .0
        }
    };

    match args.sub_command {
        Some(command) => match command {
            Commands::GetSetting { name } => {
                let setting = api.settings().get().from_variant(name).await?;
                print_setting(setting);
            }
            Commands::GetAllSettings => {
                let settings = api.settings().get_all().await?;
                println!("{:#?}", settings)
            }
            Commands::SetSetting { name, value } => {
                let valued_setting = settings::UserSettingValue::from_variant(name, &value)?;
                let settings = settings::Settings::new().set_user_value(valued_setting);
                api.settings().set(settings).await?;
            }
            Commands::Create {
                label,
                password,
                username,
                url,
                notes,
                generate,
            } => {
                let password = match password {
                    Some(p) => p,
                    None if !generate => rpassword::read_password_from_tty(Some("Password: "))?,
                    None => {
                        api.service()
                            .generate_password_with_user_settings()
                            .await?
                            .password
                    }
                };
                let hash = crypto::hash_sha1(&password);
                let mut request = password::CreatePassword::new(label, password, hash);
                request.username = username;
                request.url = url;
                request.notes = notes;
                api.password().create(request).await?;
            }
            Commands::List { folder } => {
                let folder = match folder {
                    None => {
                        api.folder()
                            .get(
                                Some(folder::Details::new().passwords().folders()),
                                Uuid::nil(),
                            )
                            .await?
                    }
                    Some(folder) => api
                        .folder()
                        .list(Some(folder::Details::new().passwords().folders()))
                        .await?
                        .into_iter()
                        .find(|f| f.versioned.label.to_lowercase().contains(&folder))
                        .ok_or(anyhow::anyhow!("Folder not found"))?,
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
                let password = api.service().generate_password(generate).await?;
                println!("{}", password.password);
            }
            Commands::Search { pattern } => search_for_password(&pattern, &api).await?,
        },
        None => match args.pattern {
            None => Err(anyhow::anyhow!(
                "No command provided, must provide a pattern to search"
            ))?,
            Some(pattern) => search_for_password(&pattern, &api).await?,
        },
    }

    if !args.no_resume_state {
        let save_state = api.get_state();
        let mut data_dir = dirs_next::data_dir().with_context(|| "no data dir available")?;
        data_dir.push(RESUME_FILE);

        crypto::store(&save_state, data_dir, &key)?;
    }

    api.disconnect().await?;

    Ok(())
}
