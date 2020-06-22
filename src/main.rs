use anyhow::Context;
use nextcloud_passwords_client::{
    password::Password,
    settings::{self, SETTINGS_NAMES, USER_SETTING_NAMES},
    AuthenticatedApi, LoginDetails, ResumeState,
};
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;

mod crypto;

const RESUME_FILE: &str = "nextpass.json";

fn print_password(password: &Password) {
    println!("{} [{}]", password.label, password.url);
    println!("   {}", password.username);
    println!("   {}", password.password);
    println!("--------------------")
}

#[derive(StructOpt)]
pub struct Args {
    #[structopt(long, short)]
    login_details: Option<std::path::PathBuf>,
    #[structopt(long, default_value = "info")]
    log_level: LevelFilter,

    #[structopt(long, env = "NEXTPASS_KEY", hide_env_values = true)]
    key: String,
    pattern: Option<String>,
    #[structopt(subcommand)]
    sub_command: Option<Commands>,

    #[structopt(long, short)]
    no_resume_state: bool,
}

#[derive(StructOpt)]
pub enum Commands {
    GetSetting {
        #[structopt(possible_values = SETTINGS_NAMES)]
        name: settings::SettingVariant,
    },
    GetAllSettings,
    SetSetting {
        #[structopt(possible_values = USER_SETTING_NAMES)]
        name: settings::UserSettings,
        value: String,
    },
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

async fn new_session(
    login_detail_path: impl AsRef<std::path::Path>,
) -> anyhow::Result<AuthenticatedApi> {
    let login_details =
        std::fs::File::open(login_detail_path).with_context(|| "Could not open login_details")?;
    let login_details: LoginDetails =
        serde_json::from_reader(login_details).with_context(|| "invalid login details")?;

    let (api, session_id) = AuthenticatedApi::new_session(login_details)
        .await
        .with_context(|| "could not open a session")?;
    log::debug!("Started new session id {}", session_id);

    Ok(api)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    TermLogger::init(args.log_level, Config::default(), TerminalMode::Mixed)?;


    let key = crypto::hash_password(args.key)?;

    let api = if args.no_resume_state {
        match args.login_details {
            Some(d) => new_session(d).await?,
            None => {
                return Err(anyhow::anyhow!(
                    "no resume state was provided neither login details"
                ))
            }
        }
    } else {
        let mut data_dir = dirs_next::data_dir().with_context(|| "no data dir available")?;
        data_dir.push(RESUME_FILE);
        if !data_dir.exists() {
            match args.login_details {
                Some(d) => new_session(d).await?,
                None => {
                    return Err(anyhow::anyhow!(
                        "no resume state was provided neither login details"
                    ))
                }
            }
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
                let setting = api.get_settings().from_variant(name).await?;
                print_setting(setting);
            }
            Commands::GetAllSettings => {
                let settings = api.get_all_settings().await?;
                println!("{:#?}", settings)
            }
            Commands::SetSetting { name, value } => {
                let valued_setting = settings::UserSettingValue::from_variant(name, &value)?;
                let settings = settings::Settings::new().set_user_value(valued_setting);
                api.set_settings(settings).await?;
            }
        },
        None => match args.pattern {
            None => Err(anyhow::anyhow!(
                "No command provided, must provide a pattern to search"
            ))?,
            Some(pattern) => {
                let pattern = pattern.to_lowercase();

                let passwords = api.list_passwords().await?;
                passwords
                    .iter()
                    .filter(|password| {
                        password.url.to_lowercase().contains(&pattern)
                            || password.label.to_lowercase().contains(&pattern)
                    })
                    .for_each(print_password);
            }
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
