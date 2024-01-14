use std::cmp::min;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

use flate2::read::GzDecoder;
use futures_util::stream::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use semver::Version;
use serde::{Deserialize, Deserializer};
use tar::Archive;
use tracing::{debug, trace};
use url::Url;

use crate::{Config, Error, Registry, RemoteVersion};

pub(crate) async fn fetch_remote_version<C: Config, R: Registry>(config: &C, registry: &R) -> crate::Result<RemoteVersion> {
	let url = registry
		.get_base_url()
		.join(registry.get_update_path(config.into()).as_str())?;

	trace!("url: {}", url);

	reqwest::get(url)
		.await?
		.json::<RemoteVersion>()
		.await
		.map_err(|err| Error::ReqwestError(err))
}

pub async fn verify_file(src: &PathBuf, required_size: u64, required_hash: String) -> crate::Result<()> {
	debug!("Verifying file integrity..");
	let file_size = src.as_path().metadata()?.len();
	assert_eq!(required_size, file_size);
	let bytes = std::fs::read(src)?;
	let file_hash = sha256::digest(&bytes);
	assert_eq!(required_hash, file_hash);
	Ok(())
}

pub async fn extract(src: &PathBuf, dst: &PathBuf) -> crate::Result<()> {
	let src_filename = src.file_name().ok_or(std::io::Error::from(ErrorKind::NotFound))?;
	debug!("Decompressing {:?} → {:?}", src_filename, dst);
	let tar_gz = File::open(src)?;
	let tar = GzDecoder::new(tar_gz);
	let mut archive = Archive::new(tar);
	Ok(archive.unpack(dst)?)
}

pub async fn download_file(
	client: &reqwest::Client,
	url: &Url,
	path: &PathBuf,
	multi_progress: Option<MultiProgress>,
	progress_style: Option<ProgressStyle>,
) -> crate::Result<()> {
	// Reqwest setup
	let filename = url.path_segments().unwrap().last().unwrap().to_string();
	let res = client.get(url.to_string().as_str()).send().await?;
	let total_size = res
		.content_length()
		.ok_or(crate::Error::InvalidContentLengthError(url.to_string()))?;

	// Indicatif setup

	let pb = if let Some(multi_progress) = multi_progress {
		let pb = multi_progress.add(ProgressBar::new(total_size));
		if let Some(style) = progress_style {
			pb.set_style(style.clone());
		} else {
			pb.set_style(ProgressStyle::default_bar());
		}
		pb.set_prefix("Downloading".to_string());
		pb.set_message(filename);
		Some(pb)
	} else {
		None
	};

	// download chunks
	let mut file = File::create(path)?;
	let mut downloaded: u64 = 0;
	let mut stream = res.bytes_stream();

	while let Some(item) = stream.next().await {
		let chunk = item?;
		file.write_all(&chunk)?;
		let new = min(downloaded + (chunk.len() as u64), total_size);
		downloaded = new;

		if let Some(pb) = &pb {
			pb.set_position(new);
		}
	}

	if let Some(pb) = &pb {
		pb.finish();
	}

	debug!("Downloaded {} to {:?}", url, path);
	return Ok(());
}

pub(crate) fn value_to_version<'de, D>(deserializer: D) -> std::result::Result<Version, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(deserializer)?;
	Version::parse(s).map_err(|err| serde::de::Error::custom(err.to_string()))
}
