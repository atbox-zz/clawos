use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()?;

    let ebpf_package = packages
        .iter()
        .find(|package| package.name == "clawos-ebpf")
        .context("ebpf package not found")?;

    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;

    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf(
        [ebpf_package],
        aya_build::Toolchain::default(),
    )
}
