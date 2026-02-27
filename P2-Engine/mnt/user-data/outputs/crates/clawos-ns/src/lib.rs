// clawos-ns — Linux namespace isolation for ClawOS
// Implements C-03, C-04, C-05 from the task spec.

use anyhow::{Context, Result};
use nix::sched::CloneFlags;
use nix::unistd::{pivot_root, chdir};
use std::fs;
use tracing::{info, warn};

pub struct IsolationConfig {
    pub new_root:       String,   // path to minimal rootfs
    pub host_uid:       u32,      // host UID that namespace root maps to (65534 = nobody)
    pub host_gid:       u32,
    pub hostname:       String,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            new_root:  "/var/lib/clawos/rootfs".into(),
            host_uid:  65534,
            host_gid:  65534,
            hostname:  "clawos-sandbox".into(),
        }
    }
}

/// Spawn a child process in a fully isolated set of Linux namespaces.
/// The child runs `f` inside:
///   - User namespace  (uid 0 → host uid 65534)
///   - PID namespace
///   - Mount namespace (with pivot_root to minimal rootfs)
///   - Network namespace (pre-configured veth by setup_netns.sh)
///   - UTS namespace (isolated hostname)
pub fn spawn_isolated<F>(config: &IsolationConfig, f: F) -> Result<nix::unistd::Pid>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWUTS;
    // Note: CLONE_NEWNET is NOT added here — network namespace is
    // pre-configured by setup_netns.sh and joined via nsenter.

    let mut stack = vec![0u8; 8 * 1024 * 1024];  // 8MB stack

    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(f),
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        ).context("clone() failed")?
    };

    // Set up UID/GID mapping from parent (MUST happen after clone, before child continues)
    setup_uid_map(child_pid, config.host_uid, config.host_gid)?;

    info!(
        child_pid = child_pid.as_raw(),
        host_uid  = config.host_uid,
        "Spawned isolated child process"
    );

    Ok(child_pid)
}

/// Write uid_map and gid_map so namespace root (0) → host nobody (65534).
fn setup_uid_map(child: nix::unistd::Pid, host_uid: u32, host_gid: u32) -> Result<()> {
    let pid = child.as_raw();

    // Deny setgroups before writing gid_map (required by kernel)
    fs::write(format!("/proc/{pid}/setgroups"), "deny")
        .context("Failed to write setgroups")?;

    // Map: inside_uid inside_gid count
    fs::write(format!("/proc/{pid}/uid_map"), format!("0 {host_uid} 1\n"))
        .context("Failed to write uid_map")?;

    fs::write(format!("/proc/{pid}/gid_map"), format!("0 {host_gid} 1\n"))
        .context("Failed to write gid_map")?;

    Ok(())
}

/// Switch root filesystem using pivot_root (safer than chroot).
/// Call this from INSIDE the mount namespace child.
pub fn do_pivot_root(new_root: &str) -> Result<()> {
    // Bind-mount new_root onto itself (required by pivot_root)
    nix::mount::mount(
        Some(new_root),
        new_root,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    ).context("bind mount of new_root failed")?;

    // Create put_old directory inside new_root
    let put_old = format!("{new_root}/.old_root");
    fs::create_dir_all(&put_old).ok();

    pivot_root(new_root, &put_old).context("pivot_root failed")?;
    chdir("/").context("chdir / after pivot_root failed")?;

    // Unmount and remove old root
    nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("umount old_root failed")?;
    fs::remove_dir("/.old_root").ok();

    info!("pivot_root complete — now inside minimal rootfs");
    Ok(())
}

/// Mount essential pseudo-filesystems inside the new namespace.
pub fn mount_minimal_fs() -> Result<()> {
    let none: Option<&str> = None;
    let nosuid_nodev_noexec =
        nix::mount::MsFlags::MS_NOSUID |
        nix::mount::MsFlags::MS_NODEV  |
        nix::mount::MsFlags::MS_NOEXEC;

    fs::create_dir_all("/proc")?;
    nix::mount::mount(none, "/proc", Some("proc"), nosuid_nodev_noexec, none)
        .context("mount /proc")?;

    fs::create_dir_all("/dev")?;
    nix::mount::mount(none, "/dev", Some("devtmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NOEXEC, none)
        .context("mount /dev")?;

    fs::create_dir_all("/tmp")?;
    nix::mount::mount(none, "/tmp", Some("tmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some("size=64m,mode=1777"))
        .context("mount /tmp")?;

    info!("Minimal filesystem mounts complete");
    Ok(())
}
