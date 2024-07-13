use std::env::temp_dir;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
#[cfg(feature = "progress")]
use indicatif::style::TemplateError;
#[cfg(feature = "progress")]
use indicatif::{MultiProgress, ProgressStyle};
use reqwest::Url;
use semver::Version;
use thiserror::Error;

mod impls;

#[derive(Error, Debug)]
pub enum Error {
	#[error(transparent)]
	ReqwestError(#[from] reqwest::Error),

	#[error(transparent)]
	UrlParseError(#[from] url::ParseError),

	#[error("Invalid version")]
	InvalidVersionError,

	#[error(transparent)]
	IoError(#[from] std::io::Error),

	#[cfg(feature = "progress")]
	#[error(transparent)]
	TemplateError(#[from] TemplateError),

	#[error("Failed to get content length from '{0}'")]
	InvalidContentLengthError(String),

	#[error("File integrity mismatch. Expected size {0}, found {1}")]
	InvalidFileSize(u64, u64),

	#[error("File checksum failed")]
	InvalidFileChecksum,

	#[error(transparent)]
	InvalidCredentialsError(anyhow::Error),
}

/// This trait is responsible to gives the base url for and the final path
/// of the update json package description
///
/// Eg:
/// ```rust
///     use cli_autoupdate::{Config, Registry};

/// 	struct MyRegistry
///     impl Registry for MyRegistry {
/// 		fn get_base_url(&self) -> Url {
/// 			Url::parse("https://registry.example/").unwrap()
///    		}
/// 		fn get_update_path<C: Config>(&self, config: &C) -> String {
///    			format!("{}.json", config.target())
///    		}
/// 		fn get_basic_auth(&self) -> anyhow::Result<Option<(String, Option<String>)>> {
/// 			Ok(None)
/// 		}
/// 	}
/// ```
pub trait Registry {
	/// base url of the repository. This is also used together with the `RemoteVersion::path`
	/// to create the final download url.
	fn get_base_url(&self) -> Url;

	/// This is the relative update json path, according to the configuration path.
	fn get_update_path<C: Config>(&self, config: &C) -> String;

	// Basic HTTP authentication (username, password)
	fn get_basic_auth(&self) -> anyhow::Result<Option<(String, Option<String>)>>;
}

/// Configuration implementation for the current package
///
/// Eg:
/// ```rust
///     use cli_autoupdate::Config;
///    	use semver::Version;
///     struct MyConfig;
///
///    	impl Config for MyConfig {
/// 		fn version(&self) -> Version {
/// 			let version_str = std::env::var("CARGO_PKG_VERSION").unwrap();
/// 			Version::parse(version_str.as_str()).unwrap()
/// 		}
///
///     fn target(&self) -> String {
///         let target = std::env::var("TARGET").unwrap_or("aarch64-apple-darwin".to_string());
///         format!("{}", target)
///     }
/// }
/// ```
pub trait Config {
	/// Should return the current package version
	fn version(&self) -> Version;

	/// Returns the package specific path, used by the registry
	fn target(&self) -> String;
}

/// Deserialized object of the remote json file, used to check for updates
/// Example:
///
/// ```json
/// 	{
/// 		"version": "2.0.0",
/// 		"datetime": "2024-01-14T14:40:43+0100",
/// 		"checksum": "726b934c8263868090490cf626b25770bbbbc98900689af512eddf9c33e9f785",
/// 		"size": 5538631,
/// 		"path": "./aarch64-apple-darwin/2.0.0/my_binary.tgz"
/// 	}
///    ```
///
#[derive(Debug, serde::Deserialize)]
pub struct RemoteVersion {
	/// version of the remote update file
	#[serde(deserialize_with = "impls::value_to_version")]
	pub version: Version,
	/// the SHA-256 checksum of the file "path"
	pub checksum: String,
	/// the size in bytes of the file "path"
	pub size: usize,
	/// update path, relative to the repository base url (Repository::get_base_url)
	pub path: String,
	/// file published datetime
	pub datetime: DateTime<Utc>,
}

pub type Result<T> = std::result::Result<T, crate::Error>;

/// Check if there's a new version available
/// Example:
/// ```rust
///
/// 	use cli_autoupdate::check_version;
///    	struct LabConfig;
/// 	struct LabRegistry;
///
/// 	#[tokio::main]
/// 	async fn main() {
/// 		let config = LabConfig;
///    		let registry = LabRegistry;
///    		let (has_update, version) = check_version(&config, &registry).await.unwrap();
///    		if has_update {
///    			let bin_name = console::style("binary_name").cyan().italic().bold();
///    			let this_version = config.version();
///    			let other_version = console::style(version.version).green();
///    			let update_url = registry.get_base_url().join(version.path.as_str()).unwrap();
///
///    			println!(
///    				"A new release of {} is available: {} → {}",
///    				bin_name, this_version, other_version
///  			);
///    			println!("Released on {}", version.datetime);
///    			println!("{}", console::style(update_url).yellow());
/// 		}
///    	}
/// ```
pub async fn check_version<C: Config, R: Registry>(config: &C, registry: &R) -> Result<(bool, RemoteVersion)> {
	impls::fetch_remote_version(config, registry)
		.await
		.and_then(|r| Ok((r.version > config.version(), r)))
}

///    Check for updates and auto-update the current binary, if a new version is available
///
pub async fn update_self<C: Config, R: Registry>(
	config: &C,
	registry: &R,
	#[cfg(feature = "progress")] multi_progress: Option<MultiProgress>,
	#[cfg(feature = "progress")] progress_style: Option<ProgressStyle>,
) -> Result<()> {
	let result = check_version(config, registry).await?;
	let remote_version = result.1;
	if result.0 {
		let remote_path = remote_version.path;
		let remote_file_path = PathBuf::from(&remote_path);
		let filename = remote_file_path
			.file_name()
			.ok_or(Error::IoError(std::io::Error::from(ErrorKind::NotFound)))?;
		let target_path = temp_dir().join(filename);
		let remote_path = registry.get_base_url().join(&remote_path.as_str())?;
		let client = reqwest::ClientBuilder::default().build().unwrap();

		#[cfg(feature = "progress")]
		let _ = impls::download_file(&client, &remote_path, &target_path, registry, multi_progress, progress_style).await?;

		#[cfg(not(feature = "progress"))]
		let _ = impls::download_file(&client, &remote_path, &target_path, registry).await?;

		let _ = impls::verify_file(&target_path, remote_version.size as u64, remote_version.checksum.clone()).await?;

		let bin_name = std::env::current_exe().or(Err(Error::IoError(std::io::Error::from(ErrorKind::NotFound))))?;
		let bin_name_path = bin_name.parent().unwrap_or(Path::new("/")).to_path_buf();
		impls::extract(&target_path, &bin_name_path).await
	} else {
		Err(Error::InvalidVersionError)
	}
}

#[cfg(test)]
mod tests {
	use std::any::type_name_of_val;

	use console::Style;
	#[cfg(feature = "progress")]
	use indicatif::{MultiProgress, ProgressStyle};
	use reqwest::Url;
	use semver::Version;
	use tracing::level_filters::LevelFilter;
	use tracing::subscriber;
	use tracing_subscriber::prelude::*;
	use tracing_subscriber::EnvFilter;

	use crate::{check_version, update_self, Config, Registry};

	struct LabRegistry;

	struct LabConfig;

	impl Registry for LabRegistry {
		fn get_base_url(&self) -> Url {
			Url::parse(format!("https://test.example.com/aot/").as_str()).unwrap()
		}

		fn get_update_path<C: Config>(&self, config: &C) -> String {
			format!("{}.json", config.target())
		}

		fn get_basic_auth(&self) -> anyhow::Result<Option<(String, Option<String>)>> {
			Ok(None)
		}
	}

	impl Config for LabConfig {
		fn version(&self) -> Version {
			let version_str = std::env::var("CARGO_PKG_VERSION").unwrap();
			Version::parse(version_str.as_str()).unwrap()
		}

		fn target(&self) -> String {
			let target = std::env::var("TARGET").unwrap_or("aarch64-apple-darwin".to_string());
			format!("{}", target)
		}
	}

	struct ArtifactoryRegistry;
	struct ArtifactoryConfig;

	impl Registry for ArtifactoryRegistry {
		fn get_base_url(&self) -> Url {
			Url::parse("https://test.artifactory.com/local/").unwrap()
		}

		fn get_update_path<C: Config>(&self, config: &C) -> String {
			format!("{}.json", config.target())
		}

		fn get_basic_auth(&self) -> anyhow::Result<Option<(String, Option<String>)>> {
			Ok(Some(("USER1".to_string(), Some("PASSWORD1".to_string()))))
		}
	}

	impl Config for ArtifactoryConfig {
		fn version(&self) -> Version {
			let version_str = std::env::var("CARGO_PKG_VERSION").unwrap();
			Version::parse(version_str.as_str()).unwrap()
		}

		fn target(&self) -> String {
			let target = std::env::var("TARGET").unwrap_or("aarch64-apple-darwin".to_string());
			format!("{}", target)
		}
	}

	#[tokio::test]
	async fn test_check_version() {
		let config = LabConfig;
		let registry = LabRegistry;
		let (has_update, version) = check_version(&config, &registry).await.unwrap();

		if has_update {
			let bin_name = console::style("binary_name").cyan().italic().bold();
			let this_version = config.version();
			let other_version = console::style(version.version).green();
			let update_url = registry.get_base_url().join(version.path.as_str()).unwrap();

			println!(
				"A new release of {} is available: {} → {}",
				bin_name, this_version, other_version
			);
			println!("Released on {}", version.datetime);
			println!("{}", console::style(update_url).yellow());
		}
	}

	#[tokio::test]
	async fn test_update_version() {
		init_logging();
		let current_exe = std::env::current_exe();
		println!("current exe: {:?}", current_exe);

		let config = LabConfig;
		let registry = LabRegistry;

		#[cfg(feature = "progress")]
		let progress_style =
			ProgressStyle::with_template("{prefix:.green.bold} [{bar:40.cyan/blue.bold}] {percent:>5}% [ETA {eta}] {msg} ")
				.unwrap()
				.progress_chars("=> ");
		#[cfg(feature = "progress")]
		let multi_progress = MultiProgress::new();

		#[cfg(feature = "progress")]
		let result = update_self(&config, &registry, Some(multi_progress), Some(progress_style)).await;

		#[cfg(not(feature = "progress"))]
		let result = update_self(&config, &registry).await;

		match result {
			Ok(_) => {}
			Err(err) => {
				println!("Error checking for version update:");
				println!("{}", console::style(err.to_string()).red().italic());
			}
		}
	}

	#[tokio::test]
	async fn test_check_version_with_basic_auth() {
		let config = ArtifactoryConfig;
		let registry = ArtifactoryRegistry;

		let result = check_version(&config, &registry).await;

		match result {
			Ok((has_update, version)) => {
				if has_update {
					let bin_name = console::style("binary_name").cyan().italic().bold();
					let this_version = config.version();
					let other_version = console::style(version.version).green();
					let update_url = registry.get_base_url().join(version.path.as_str()).unwrap();
					println!(
						"A new release of {} is available: {} → {}",
						bin_name, this_version, other_version
					);
					println!("Released on {}", version.datetime);
					println!("{}", console::style(update_url).yellow());
				}
			}
			Err(err) => {
				println!("Error checking for version update:");
				println!("{}", console::style(err.to_string()).red().italic());
				println!("Error type: {:?}", type_name_of_val(&err));

				match err {
					crate::Error::ReqwestError(err) => {
						println!("ReqwestError: {:?}", err);
					}
					crate::Error::UrlParseError(err) => {
						println!("UrlParseError: {:?}", err);
					}
					crate::Error::InvalidVersionError => {
						println!("InvalidVersionError");
					}
					crate::Error::IoError(err) => {
						println!("IoError: {:?}", err);
					}
					crate::Error::InvalidContentLengthError(err) => {
						println!("InvalidContentLengthError: {:?}", err);
					}
					crate::Error::InvalidFileSize(size, found) => {
						println!("InvalidFileSize: size: {}, found: {}", size, found);
					}
					crate::Error::InvalidFileChecksum => {
						println!("InvalidFileChecksum");
					}
					crate::Error::InvalidCredentialsError(err) => {
						println!("InvalidCredentialsError: {:?}", err);
					}
				}
			}
		}
	}

	#[tokio::test]
	async fn test_update_version_with_basic_auth() {
		init_logging();
		let current_exe = std::env::current_exe();
		println!("current exe: {:?}", current_exe);

		let config = ArtifactoryConfig;
		let registry = ArtifactoryRegistry;

		#[cfg(feature = "progress")]
		let progress_style =
			ProgressStyle::with_template("{prefix:.green.bold} [{bar:40.cyan/blue.bold}] {percent:>5}% [ETA {eta}] {msg} ")
				.unwrap()
				.progress_chars("=> ");
		#[cfg(feature = "progress")]
		let multi_progress = MultiProgress::new();

		#[cfg(feature = "progress")]
		let result = update_self(&config, &registry, Some(multi_progress), Some(progress_style)).await;

		#[cfg(not(feature = "progress"))]
		let result = update_self(&config, &registry).await;

		match result {
			Ok(_) => {}
			Err(err) => {
				println!("Error checking for version update:");
				println!("{}", console::style(err.to_string()).red().italic());
			}
		}
	}

	fn init_logging() {
		let registry = tracing_subscriber::Registry::default();

		let term_subscriber = logging_subscriber::LoggingSubscriberBuilder::default()
			.with_time(true)
			.with_level(true)
			.with_target(true)
			.with_file(false)
			.with_line_number(false)
			.with_min_level(LevelFilter::TRACE)
			.with_format_level(logging_subscriber::LevelOutput::Long)
			.with_default_style(Style::default().dim())
			.with_level_style_warn(Style::new().color256(220).bold())
			.with_level_style_trace(Style::new().magenta().bold())
			.with_date_time_style(Style::new().white())
			.build();

		let filter = EnvFilter::builder()
			.with_default_directive(LevelFilter::TRACE.into())
			.from_env()
			.unwrap()
			.add_directive("hyper::proto=warn".parse().unwrap())
			.add_directive("hyper::client=warn".parse().unwrap());

		let subscriber = registry.with(filter).with(term_subscriber);
		subscriber::set_global_default(subscriber).unwrap();
	}
}
