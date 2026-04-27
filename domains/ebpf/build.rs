use anyhow::{Context as _};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        aya_build::cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("failed to fetch cargo metadata")?
            .packages
            .into_iter()
            .filter(|p| p.name == "clawos-ebpf")
            .filter_map(|p| aya_build::Package::try_from(p).ok()),
        aya_build::Toolchain::default(),
    )
}
