//! Packs an app for a unit to install:
//!
//!   edge-pack pack <deploy dir> <out dir> --version <tag> --epoch <n>
//!       --artifact <repository> --layout <oci layout>... [--image KEY=ref@digest]...
//!       [--notes <file>] [--secret-owner <namespace>/<serviceaccount>
//!       --secret-label <key>=<value>]
//!                       the app staged at <out dir>, with its SHA256SUMS to sign
//!   edge-pack seal <out dir> [<SHA256SUMS.sigstore.json>] <app.tar>
//!                       the staged app and any signature as the app's tar

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pack") => pack(&args[1..]),
        Some("seal") if matches!(args.len(), 3 | 4) => {
            let sig = match &args[2..args.len() - 1] {
                [s] => Some(std::fs::read(s).with_context(|| format!("reading {s}"))?),
                _ => None,
            };
            let out = Path::new(&args[args.len() - 1]);
            edge_bundle::seal(Path::new(&args[1]), sig.as_deref(), 0, out)
        }
        _ => {
            bail!(
                "usage: edge-pack pack <deploy> <out> … | edge-pack seal <out> [<signature>] <tar>"
            )
        }
    }
}

fn pack(args: &[String]) -> anyhow::Result<()> {
    let [deploy, out, flags @ ..] = args else {
        bail!(
            "edge-pack pack <deploy dir> <out dir> --version … --epoch … --artifact … --layout …"
        );
    };
    let mut one: BTreeMap<&str, &str> = BTreeMap::new();
    let (mut layouts, mut images) = (Vec::new(), BTreeMap::new());
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let v = it.next().with_context(|| format!("{flag} wants a value"))?;
        match flag.as_str() {
            "--layout" => layouts.push(PathBuf::from(v)),
            "--image" => {
                let (k, r) = v
                    .split_once('=')
                    .with_context(|| format!("{v:?} is not KEY=ref"))?;
                ensure!(
                    images.insert(k.to_string(), r.to_string()).is_none(),
                    "{k} given twice"
                );
            }
            f @ ("--version" | "--epoch" | "--artifact" | "--notes" | "--secret-owner"
            | "--secret-label") => {
                ensure!(one.insert(f, v).is_none(), "{f} given twice");
            }
            f => bail!("{f} is no flag of edge-pack pack"),
        }
    }
    let get = |f: &str| one.get(f).copied().with_context(|| format!("give {f}"));
    let notes = one
        .get("--notes")
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading {p}")))
        .transpose()?;
    let secret_owner = match (one.get("--secret-owner"), one.get("--secret-label")) {
        (None, None) => None,
        (Some(o), Some(l)) => {
            let (namespace, service_account) = o
                .split_once('/')
                .with_context(|| format!("{o:?} is not <namespace>/<serviceaccount>"))?;
            let (k, v) = l
                .split_once('=')
                .with_context(|| format!("{l:?} is not <key>=<value>"))?;
            Some(edge_pack::SecretOwner {
                namespace: namespace.into(),
                service_account: service_account.into(),
                label: (k.into(), v.into()),
            })
        }
        _ => bail!("give --secret-owner and --secret-label together"),
    };
    edge_pack::pack(
        &edge_pack::Pack {
            deploy: Path::new(deploy),
            layouts: &layouts,
            images: &images,
            version: get("--version")?,
            epoch: get("--epoch")?.parse().context("--epoch is not a number")?,
            artifact: get("--artifact")?,
            notes: notes.as_deref(),
            secret_owner: secret_owner.as_ref(),
        },
        Path::new(out),
    )?;
    println!("{}", Path::new(out).join(edge_bundle::SUMS).display());
    Ok(())
}
