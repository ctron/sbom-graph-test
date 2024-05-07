mod db;
mod rel;

use crate::db::Database;
use clap::Parser;
use serde_json::Value;
use spdx_rs::models::SPDX;
use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use tokio::task::spawn_blocking;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_log() {
    tracing_subscriber::registry()
        // Filter spans based on the RUST_LOG env var.
        .with(tracing_subscriber::EnvFilter::from_default_env())
        // Send a copy of all spans to stdout as JSON.
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_level(true)
                .compact(),
        )
        // Install this registry as the global tracing registry.
        .try_init()
        .expect("error initializing logging");
}

#[derive(Clone, Debug, clap::Parser)]
pub struct Cli {
    #[arg(env = "ROOT_DIR", default_value = "data")]
    root: PathBuf,
    #[arg(short, long, env = "PREFIXES", value_delimiter = ',')]
    prefix: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_log();
    cli.run().await.unwrap();
}

#[derive(Default)]
struct DetectDuplicates(pub HashMap<String, Vec<PathBuf>>);

impl DetectDuplicates {
    pub fn dump(self) {
        for (k, v) in self.0 {
            if v.len() > 1 {
                log::warn!("Duplicates: {k}");
                for f in v {
                    log::warn!("    {}", f.display());
                }
            }
        }
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let mut db =
            Database::new("host=localhost port=5432 user=postgres password=postgres").await?;

        #[allow(unused_mut)]
        let mut dup = DetectDuplicates::default();

        for entry in walkdir::WalkDir::new(&self.root) {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".bz2") {
                continue;
            }

            // test filter

            if !self.accepted(entry.path()) {
                continue;
            }

            // process

            // process(entry.path(), &mut dup).await?;
            process(entry.path(), &mut db).await?;
        }

        dup.dump();

        Ok(())
    }

    fn accepted(&self, path: &Path) -> bool {
        if self.prefix.is_empty() {
            return true;
        }

        let file = path
            .file_name()
            .unwrap_or_else(|| path.as_os_str())
            .to_string_lossy();

        for prefix in &self.prefix {
            if file.starts_with(prefix) {
                return true;
            }
        }

        false
    }
}

trait Processor {
    async fn process(&mut self, path: &Path, sbom: SPDX) -> anyhow::Result<()>;
}

impl Processor for Database {
    async fn process(&mut self, _path: &Path, sbom: SPDX) -> anyhow::Result<()> {
        self.ingest(sbom).await
    }
}

impl Processor for DetectDuplicates {
    async fn process(&mut self, path: &Path, sbom: SPDX) -> anyhow::Result<()> {
        self.0
            .entry(sbom.document_creation_information.spdx_document_namespace)
            .or_default()
            .push(path.to_path_buf());

        Ok(())
    }
}

impl<F, Fut> Processor for F
where
    F: FnMut(SPDX) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    async fn process(&mut self, _path: &Path, sbom: SPDX) -> anyhow::Result<()> {
        (self)(sbom).await
    }
}

async fn process<P: Processor>(path: &Path, p: &mut P) -> anyhow::Result<()> {
    log::info!("Parsing: {}", path.display());

    let file = path.to_path_buf();
    let sbom = spawn_blocking(move || {
        let processed = PathBuf::from(format!("{}.processed", file.display()));

        if processed.exists() {
            return Ok(serde_json::from_reader::<_, SPDX>(BufReader::new(
                File::open(processed)?,
            ))?);
        }

        log::info!("Processing: {}", file.display());

        let reader = BufReader::new(File::open(&file)?);
        let reader = bzip2::bufread::BzDecoder::new(reader);
        let mut spdx = serde_json::from_reader(reader)?;
        fix_license(&mut spdx);
        let spdx: SPDX = serde_json::from_value(spdx)?;

        let tmp = PathBuf::from(format!("{}.tmp", file.display()));
        serde_json::to_writer(BufWriter::new(File::create(&tmp)?), &spdx)?;
        std::fs::rename(tmp, processed)?;

        Ok::<_, anyhow::Error>(spdx)
    })
    .await??;

    log::info!(
        "Processing SBOM: {} / {}",
        sbom.document_creation_information.document_name,
        sbom.document_creation_information.spdx_document_namespace
    );

    // db.ingest(sbom).await?;

    p.process(path, sbom).await?;

    Ok(())
}

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(json: &mut Value) -> bool {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    log::debug!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;
                }
            }
        }
    }

    changed
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_args() {
        Cli::command().debug_assert()
    }
}
