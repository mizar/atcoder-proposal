use askama::Template as _;
use build_info::build_info;
use camino::Utf8Path;
use cargo_metadata::{CargoOpt, Dependency, DependencyKind, MetadataCommand, Package};
use clap::Parser as _;
use eyre::{ensure, eyre};
use indexmap::IndexMap;
use itertools::Itertools as _;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write,
};

#[allow(clippy::enum_variant_names)]
#[derive(clap::Parser)]
enum Args {
    GenToml(ArgsGenToml),
    GenSpecs(ArgsGenSpecs),
    GenCommand(ArgsGenCommand),
    GenLicenseUrls(ArgsGenLicenseUrls),
}

#[derive(clap::Parser)]
struct ArgsGenToml {
    spdx_data: String,
}

#[derive(clap::Parser)]
struct ArgsGenSpecs {}

#[derive(clap::Parser)]
struct ArgsGenCommand {}

#[derive(clap::Parser)]
struct ArgsGenLicenseUrls {}

#[derive(Debug, Deserialize, Default)]
struct Clarifications {
    #[serde(default)]
    clarify: HashMap<String, Clarification>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Clarification {
    SingleClarification(Box<InnerClarification>),
    ClarificationList(Vec<InnerClarification>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct InnerClarification {
    /// The optional version constraint. Defaults to any version.
    version: Option<semver::VersionReq>,

    /// The SPDX license expression for the entire package.
    #[serde(deserialize_with = "expression_from_str")]
    expression: spdx::Expression,

    /// List of files containing license information and their hashes.
    license_files: Vec<LicenseFile>,

    /// List of files that should be skipped as they don't contain license information.
    #[serde(default)]
    skip_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LicenseFile {
    path: String,
    hash: u32,
    /// The SPDX license expression for the entire package.
    #[serde(deserialize_with = "expression_from_str")]
    license: spdx::Expression,
}

/// `#[serde(deserialize_with)]` handler for parsing as an `spdx::Expression`.
fn expression_from_str<'de, D>(deserializer: D) -> Result<spdx::Expression, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = spdx::Expression;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            spdx::Expression::parse(s).map_err(|err| E::custom(err.to_string()))
        }
    }

    deserializer.deserialize_str(Visitor)
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    match Args::parse() {
        Args::GenToml(args) => gen_toml(args),
        Args::GenSpecs(args) => gen_specs(args),
        Args::GenCommand(args) => gen_command(args),
        Args::GenLicenseUrls(args) => gen_license_urls(args),
    }
}

fn gen_toml(ArgsGenToml { spdx_data }: ArgsGenToml) -> eyre::Result<()> {
    let mut cargo_toml = include_str!("../../Cargo.toml").parse::<toml_edit::DocumentMut>()?;
    cargo_toml.remove("workspace");

    let clarify: Clarifications = toml::from_str(include_str!("../../clarify.toml"))?;
    let clarify_vec = clarify
        .clarify
        .iter()
        .flat_map(|(name, clarification)| match clarification {
            Clarification::SingleClarification(clarification) => {
                vec![(name.clone(), clarification.as_ref())]
            }
            Clarification::ClarificationList(clarifications) => clarifications
                .iter()
                .map(|clarification| (name.clone(), clarification))
                .collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>();

    let mut store = askalono::Store::new();
    store
        .load_spdx(std::path::Path::new(spdx_data.as_str()), false)
        .unwrap();

    let md = MetadataCommand::new()
        .features(CargoOpt::AllFeatures)
        .exec()?;
    let root_package = &md.root_package().ok_or_else(|| eyre!("no root package"))?;
    let root_dependencies = root_package
        .dependencies
        .iter()
        .map(|d| (d.name.clone(), d.req.to_string()))
        .collect::<HashSet<_>>();

    let packages = md
        .packages
        .iter()
        .map(|p| ((&p.name, &p.version), p))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();

    let mut libraries = String::new();
    for package in packages.iter().filter(|p| p.name.as_str() != "main") {
        let indirect = !root_dependencies.contains(&(
            package.name.clone(),
            ["=", package.version.to_string().as_str()].join(""),
        ));
        let licensee: spdx::Expression = spdx::Expression::parse(
            package
                .license
                .as_ref()
                .unwrap()
                .split("/")
                .map(str::trim)
                .join(" OR ")
                .as_str(),
        )?;
        let clar = clarify_vec.iter().find(|(name, clar)| {
            name == &package.name
                && clar
                    .version
                    .as_ref()
                    .map_or(true, |v| v.matches(&package.version))
        });
        writeln!(
            &mut libraries,
            "library.{name}-{version_h} = {{ license = [",
            name = package.name,
            version_h = package
                .version
                .to_string()
                .replace(".", "-")
                .replace("+", "-"),
        )?;
        writeln!(
            &mut libraries,
            "# Cargo.toml (package.license) [{license}]",
            license = licensee.to_string(),
        )?;
        if let Some((_, clar)) = clar {
            writeln!(
                &mut libraries,
                "# clarifyed [{license}]",
                license = clar.expression.to_string(),
            )?;
        }
        for expr_node in licensee.iter() {
            if let spdx::expression::ExprNode::Req(expr_req) = expr_node {
                writeln!(
                    &mut libraries,
                    "    {{ name = '{license}', url = 'https://docs.rs/crate/{name}/{version}/source/Cargo.toml' }},",
                    license = expr_req.req.license.id().unwrap().name,
                    name = package.name,
                    version = package.version,
                )?;
            }
        }
        let base_dir = package.manifest_path.parent().unwrap();
        for dir_entry in ignore::Walk::new(base_dir).filter_map(Result::ok) {
            if !dir_entry.path().is_file() {
                continue;
            }
            let filename = dir_entry.path().file_name().unwrap().to_str().unwrap();
            if !["LICENSE", "COPYING", "COPYRIGHT"]
                .iter()
                .any(|s| filename.to_uppercase().contains(s))
            {
                continue;
            }
            let path = dir_entry.path().strip_prefix(base_dir)?.to_str().unwrap();
            if !path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
            {
                eprintln!("skip: {}", path);
                continue;
            }
            let file_string = std::fs::read_to_string(dir_entry.path())?;
            let matched = store.analyze(&file_string.clone().into());
            let hash = twox_hash::XxHash32::oneshot(0, file_string.as_bytes());

            if let Some((_, clar)) = clar {
                writeln!(
                    &mut libraries,
                    "# {path} [{matched}] hash = 0x{hash:08x}",
                    matched = match matched {
                        askalono::Match {
                            score,
                            name,
                            license_type: _,
                            data: _,
                        } if score >= 0.9 => {
                            format!(
                                "{name} (confidence {score:.4}){ex}",
                                ex = if name == "Pixar" {
                                    // Pixar maybe Apache-2.0
                                    ", maybe Apache-2.0"
                                } else {
                                    ""
                                }
                            )
                        }
                        _ => "unknown".to_string(),
                    },
                )?;

                if clar.skip_files.iter().any(|p| p.as_str() == path) {
                    writeln!(
                        &mut libraries,
                        "# clarified skip: {path} [{matched}] hash = 0x{hash:08x}",
                        matched = match matched {
                            askalono::Match {
                                score,
                                name,
                                license_type: _,
                                data: _,
                            } if score >= 0.9 => {
                                format!(
                                    "{name} (confidence {score:.4}){ex}",
                                    ex = if name == "Pixar" {
                                        // Pixar maybe Apache-2.0
                                        ", maybe Apache-2.0"
                                    } else {
                                        ""
                                    }
                                )
                            }
                            _ => "unknown".to_string(),
                        },
                    )?;
                } else if let Some(license_file) = clar
                    .license_files
                    .iter()
                    .find(|f| f.path == path && f.hash == hash)
                {
                    writeln!(
                        &mut libraries,
                        "# clarifyed: {path} [{license}] hash = 0x{hash:08x}",
                        license = license_file.license.to_string(),
                    )?;
                    for expr_node in license_file.license.iter() {
                        if let spdx::expression::ExprNode::Req(exp) = expr_node {
                            writeln!(
                                &mut libraries,
                                "    {{ name = '{license}', url = 'https://docs.rs/crate/{name}/{version}/source/{path}' }},",
                                license = exp.req,
                                name = package.name,
                                version = package.version,
                                path = path,
                            )?;
                        }
                    }
                } else {
                    panic!(
                        "Unclarified: {package} {version} {path} hash = 0x{hash:08x}\n{clar:?}",
                        package = package.name,
                        version = package.version,
                        clar = clar,
                    );
                }
            } else {
                writeln!(
                    &mut libraries,
                    "# {path} [{matched}] hash = 0x{hash:08x}",
                    matched = match matched {
                        askalono::Match {
                            score,
                            name,
                            license_type: _,
                            data: _,
                        } if score >= 0.9 => {
                            format!(
                                "{name} (confidence {score:.4}){ex}",
                                ex = if name == "Pixar" {
                                    // Pixar maybe Apache-2.0
                                    ", maybe Apache-2.0"
                                } else {
                                    ""
                                }
                            )
                        }
                        _ => panic!(
                            "Unmatched: {package} {path} hash = 0x{hash:08x}",
                            package = package.name
                        ),
                    },
                )?;

                let license_name = match matched {
                    askalono::Match {
                        score,
                        name,
                        license_type: _,
                        data: _,
                    } if score >= 0.9 => {
                        if name == "Pixar" {
                            // Pixar maybe Apache-2.0
                            "Apache-2.0"
                        } else {
                            name
                        }
                    }
                    _ => panic!(
                        "Unmatched: {package} {path} hash = 0x{hash:08x}",
                        package = package.name
                    ),
                };

                writeln!(
                    &mut libraries,
                    "    {{ name = '{license}', url = 'https://docs.rs/crate/{name}/{version}/source/{path}' }},",
                    license = license_name,
                    name = package.name,
                    version = package.version,
                    path = dir_entry
                        .path()
                        .strip_prefix(base_dir)?
                        .to_str()
                        .unwrap()
                        .replace("\\", "/"),
                )?;
            }
        }
        writeln!(
            &mut libraries,
            "], indirect = {indirect}, version = '{version}' }}",
            version = package.version,
        )?;
    }

    let git_rev = build_info()
        .version_control
        .as_ref()
        .unwrap()
        .git()
        .unwrap()
        .commit_id
        .clone();

    let commands = CommandTemplate {
        rust_version: build_info().compiler.version.to_string(),
        rust_channel: match build_info().compiler.channel {
            build_info::CompilerChannel::Stable => build_info().compiler.version.to_string(),
            build_info::CompilerChannel::Beta => "beta".to_string(),
            build_info::CompilerChannel::Nightly => "nightly".to_string(),
            build_info::CompilerChannel::Dev => "dev".to_string(),
        },
        cargo_toml: cargo_toml.to_string().trim_start(),
        git_rev: &git_rev,
    }
    .render()?;

    let install_script = ScriptTemplate {
        rust_version: &build_info().compiler.version.to_string(),
        commands: commands.trim_end(),
        libraries: libraries.trim_end(),
        git_rev: &git_rev,
    }
    .render()?;

    println!("{install_script}");

    return Ok(());

    build_info!(fn build_info);

    #[derive(askama::Template)]
    #[template(path = "./install-command.bash.txt")]
    struct CommandTemplate<'a> {
        rust_version: String,
        rust_channel: String,
        cargo_toml: &'a str,
        git_rev: &'a str,
    }

    #[derive(askama::Template)]
    #[template(path = "./install-script.toml.txt")]
    struct ScriptTemplate<'a> {
        rust_version: &'a str,
        commands: &'a str,
        libraries: &'a str,
        git_rev: &'a str,
    }
}

fn gen_specs(ArgsGenSpecs {}: ArgsGenSpecs) -> eyre::Result<()> {
    let md = MetadataCommand::new()
        .features(CargoOpt::AllFeatures)
        .exec()?;
    let root_package = &md.root_package().ok_or_else(|| eyre!("no root package"))?;

    let specs = normal_crates_io_deps(root_package)?
        .map(|Dependency { name, req, .. }| (&**name, format!("{name}@{req}")))
        .collect();

    for spec in reorder(specs, &root_package.manifest_path)? {
        println!("{spec}");
    }
    Ok(())
}

fn gen_command(ArgsGenCommand {}: ArgsGenCommand) -> eyre::Result<()> {
    let mut cargo_toml = include_str!("../../Cargo.toml").parse::<toml_edit::DocumentMut>()?;
    cargo_toml.remove("workspace");

    let install_command = Template {
        rust_version: build_info().compiler.version.to_string(),
        rust_channel: match build_info().compiler.channel {
            build_info::CompilerChannel::Stable => build_info().compiler.version.to_string(),
            build_info::CompilerChannel::Beta => "beta".to_string(),
            build_info::CompilerChannel::Nightly => "nightly".to_string(),
            build_info::CompilerChannel::Dev => "dev".to_string(),
        },
        cargo_toml: cargo_toml.to_string().trim_start(),
        git_rev: &build_info()
            .version_control
            .as_ref()
            .unwrap()
            .git()
            .unwrap()
            .commit_id,
    }
    .render()?;
    println!("{install_command}");
    return Ok(());

    build_info!(fn build_info);

    #[derive(askama::Template)]
    #[template(path = "./install-command.bash.txt")]
    struct Template<'a> {
        rust_version: String,
        rust_channel: String,
        cargo_toml: &'a str,
        git_rev: &'a str,
    }
}

fn gen_license_urls(ArgsGenLicenseUrls {}: ArgsGenLicenseUrls) -> eyre::Result<()> {
    let md = MetadataCommand::new()
        .features(CargoOpt::AllFeatures)
        .exec()?;
    let root_package = &md.root_package().ok_or_else(|| eyre!("no root package"))?;

    let packages = md
        .packages
        .iter()
        .map(|p| ((&*p.name, p.version.to_string()), p))
        .collect::<HashMap<_, _>>();

    let urls = normal_crates_io_deps(root_package)?
        .map(|Dependency { name, req, .. }| {
            let version = req.to_string().trim_start_matches('=').to_owned();
            let Package {
                name,
                version,
                manifest_path,
                ..
            } = packages[&(&**name, version)];
            let manifest_dir = manifest_path.parent().unwrap();

            // 一部のクレートは暫定対応
            if ["amplify_derive", "amplify_num"].contains(&&**name) {
                let sha1 = read_git_sha1(manifest_dir)?;
                return Ok((
                    &**name,
                    format!("https://github.com/rust-amplify/rust-amplify/blob/{sha1}/LICENSE"),
                ));
            }
            /*
            if name == "proconio" {
                let sha1 = read_git_sha1(manifest_dir)?;
                return Ok((
                    "proconio",
                    format!("https://github.com/statiolake/proconio-rs/tree/{sha1}"),
                ));
            }
            */
            if name == "nalgebra" {
                // clarify.tomlを参照のこと
                return Ok((
                    "nalgebra",
                    format!("https://docs.rs/crate/nalgebra/{version}/source/Cargo.toml.orig"),
                ));
            }
            if ["argio", "counter", "pathfinding", "bitset-fixed"].contains(&&**name) {
                return Ok((
                    name,
                    format!("https://docs.rs/crate/{name}/{version}/source/Cargo.toml.orig"),
                ));
            }

            let url = format!("https://docs.rs/crate/{name}/{version}/source/");
            let url = if manifest_dir.join("LICENSE").exists() {
                format!("{url}LICENSE")
            } else if manifest_dir.join("LICENSE.txt").exists() {
                format!("{url}LICENSE.txt")
            } else {
                url
            };
            Ok((&**name, url))
        })
        .collect::<eyre::Result<_>>()?;

    println!(
        "{}",
        Template {
            crate_licenses: reorder(urls, &root_package.manifest_path)?.collect(),
        }
        .render()?,
    );
    return Ok(());

    fn read_git_sha1(manifest_dir: &Utf8Path) -> eyre::Result<String> {
        let path = manifest_dir.join(".cargo_vcs_info.json");
        let json = &fs_err::read_to_string(path)?;
        let CargoVcsInfo { git: Git { sha1 } } = serde_json::from_str(json)?;
        return Ok(sha1);

        #[derive(Deserialize)]
        struct CargoVcsInfo {
            git: Git,
        }

        #[derive(Deserialize)]
        struct Git {
            sha1: String,
        }
    }

    #[derive(askama::Template)]
    #[template(path = "./license-url.txt")]
    struct Template {
        crate_licenses: Vec<String>,
    }
}

fn normal_crates_io_deps(
    root_package: &Package,
) -> eyre::Result<impl Iterator<Item = &Dependency>> {
    root_package
        .dependencies
        .iter()
        .filter(|Dependency { source, kind, .. }| {
            source.as_deref() == Some("registry+https://github.com/rust-lang/crates.io-index")
                && *kind == DependencyKind::Normal
        })
        .map(|dep| {
            ensure!(dep.uses_default_features, "not yet suppoorted");
            ensure!(!dep.optional, "not yet suppoorted");
            ensure!(dep.target.is_none(), "not yet suppoorted");
            ensure!(dep.rename.is_none(), "not yet suppoorted");
            Ok(dep)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(IntoIterator::into_iter)
}

fn reorder<'a, V: 'a>(
    items: HashMap<&'a str, V>,
    manifest_path: &Utf8Path,
) -> eyre::Result<impl Iterator<Item = V> + 'a> {
    let Manifest { dependencies } = toml::from_str(&fs_err::read_to_string(manifest_path)?)?;

    return Ok(items
        .into_iter()
        .sorted_by_key(move |(name, _)| {
            dependencies
                .keys()
                .enumerate()
                .find(|&(_, name_)| name_ == name)
                .map(|(i, _)| i)
        })
        .map(|(_, v)| v));

    #[derive(Deserialize)]
    struct Manifest {
        dependencies: IndexMap<String, toml::Value>,
    }
}
