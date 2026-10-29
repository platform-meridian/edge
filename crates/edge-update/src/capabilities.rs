//! The node's capabilities (ADR-0015 §2): what the host offers that an app
//! can need, each the node label `capability.platform.meridian/<name>`,
//! which the platform operator's requirement check matches. The names are
//! `meridian_app`'s closed set (core's `artifact::Capability`).
//!
//! On the appliance three are the appliance's by construction: the storage
//! provisioner (`crate::volumes`) serves the default class, the appliance
//! runs its mission path host-networked, and the edge application
//! administers the host it is on (`host-admin`). Two are the hardware's,
//! read from the host's sysfs: a serial port, and a GPU.
//!
//! Applied server-side under one field manager, so a capability the host no
//! longer has loses its label, and no other label is touched.

use std::path::{Path, PathBuf};
use std::time::Duration;

use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, Patch, PatchParams};

const PREFIX: &str = "capability.platform.meridian/";
const MANAGER: &str = "edge-capabilities";
const EVERY: Duration = Duration::from_secs(300);

/// A capability by its `meridian_app` name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    PersistentStorage,
    HostNetwork,
    HostAdmin,
    SerialDevices,
    Gpu,
}

impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Capability::PersistentStorage => "persistent-storage",
            Capability::HostNetwork => "host-network",
            Capability::HostAdmin => "host-admin",
            Capability::SerialDevices => "serial-devices",
            Capability::Gpu => "gpu",
        }
    }

    pub fn label(self) -> String {
        format!("{PREFIX}{}", self.name())
    }
}

/// PCI vendors whose display controllers are GPUs: NVIDIA, AMD, Intel. A
/// virtual machine's display (Bochs, virtio, QXL, VMware, Cirrus) is not one.
const GPU_VENDORS: &[&str] = &["0x10de", "0x1002", "0x8086"];

/// What the host at `sys` (its `/sys`) offers.
pub fn offered(sys: &Path) -> Vec<Capability> {
    let mut out = vec![
        Capability::PersistentStorage,
        Capability::HostNetwork,
        Capability::HostAdmin,
    ];
    if serial(sys) {
        out.push(Capability::SerialDevices);
    }
    if gpu(sys) {
        out.push(Capability::Gpu);
    }
    out
}

fn entries(dir: PathBuf) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
}

fn read(p: PathBuf) -> String {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// A USB or ACM serial adapter, or a UART: the kernel's legacy `ttyS` ports
/// exist whether or not one is there, and say `type` 0 (unknown) when not.
fn serial(sys: &Path) -> bool {
    entries(sys.join("class/tty")).any(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if name.starts_with("ttyUSB") || name.starts_with("ttyACM") {
            return true;
        }
        name.starts_with("ttyS") && !matches!(read(p.join("type")).as_str(), "" | "0")
    })
}

/// A PCI display controller (class 0x03xxxx) from a GPU vendor.
fn gpu(sys: &Path) -> bool {
    entries(sys.join("bus/pci/devices")).any(|p| {
        read(p.join("class")).starts_with("0x03")
            && GPU_VENDORS.contains(&read(p.join("vendor")).as_str())
    })
}

/// The labels `offered` puts on the node, every other capability's absent.
pub fn patch(offered: &[Capability]) -> serde_json::Value {
    let labels: serde_json::Map<String, serde_json::Value> =
        offered.iter().map(|c| (c.label(), "true".into())).collect();
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": { "labels": labels },
    })
}

/// Labels the node `node` with what the host offers, now and every few minutes.
pub async fn run(client: kube::Client, node: String, sys: PathBuf) {
    let nodes: Api<Node> = Api::all(client);
    let params = PatchParams::apply(MANAGER).force();
    let mut said = None;
    loop {
        let have = offered(&sys);
        let mut body = patch(&have);
        body["metadata"]["name"] = node.clone().into();
        match nodes.patch(&node, &params, &Patch::Apply(&body)).await {
            Ok(_) if said.as_ref() != Some(&have) => {
                let names: Vec<&str> = have.iter().map(|c| c.name()).collect();
                tracing::info!(node = %node, capabilities = ?names, "node labelled");
                said = Some(have);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(node = %node, error = %e, "node not labelled"),
        }
        tokio::time::sleep(EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for tty in ["ttyS0", "ttyS1", "tty0"] {
            std::fs::create_dir_all(d.path().join("class/tty").join(tty)).unwrap();
            std::fs::write(d.path().join("class/tty").join(tty).join("type"), "0\n").unwrap();
        }
        // A virtual machine's display.
        let vga = d.path().join("bus/pci/devices/0000:00:01.0");
        std::fs::create_dir_all(&vga).unwrap();
        std::fs::write(vga.join("class"), "0x030000\n").unwrap();
        std::fs::write(vga.join("vendor"), "0x1234\n").unwrap();
        d
    }

    #[test]
    fn a_bare_host_offers_storage_host_networking_and_its_administration() {
        let d = sys();
        let bare = [
            Capability::PersistentStorage,
            Capability::HostNetwork,
            Capability::HostAdmin,
        ];
        assert_eq!(offered(d.path()), bare);
        assert_eq!(offered(&d.path().join("absent")), bare);
    }

    #[test]
    fn a_serial_port_or_adapter_is_serial_devices() {
        let d = sys();
        std::fs::write(d.path().join("class/tty/ttyS1/type"), "4\n").unwrap();
        assert!(offered(d.path()).contains(&Capability::SerialDevices));
        let d = sys();
        std::fs::create_dir_all(d.path().join("class/tty/ttyUSB0")).unwrap();
        assert!(offered(d.path()).contains(&Capability::SerialDevices));
    }

    #[test]
    fn a_gpu_vendors_display_controller_is_a_gpu() {
        let d = sys();
        let card = d.path().join("bus/pci/devices/0000:01:00.0");
        std::fs::create_dir_all(&card).unwrap();
        std::fs::write(card.join("class"), "0x030200\n").unwrap();
        std::fs::write(card.join("vendor"), "0x10de\n").unwrap();
        assert!(offered(d.path()).contains(&Capability::Gpu));
        std::fs::write(card.join("class"), "0x020000\n").unwrap();
        assert!(!offered(d.path()).contains(&Capability::Gpu), "a NIC");
    }

    #[test]
    fn the_patch_labels_what_is_offered_and_nothing_else() {
        let p = patch(&[Capability::PersistentStorage, Capability::Gpu]);
        assert_eq!(
            p["metadata"]["labels"],
            serde_json::json!({
                "capability.platform.meridian/persistent-storage": "true",
                "capability.platform.meridian/gpu": "true",
            })
        );
        for (c, name) in [
            (Capability::PersistentStorage, "persistent-storage"),
            (Capability::HostNetwork, "host-network"),
            (Capability::HostAdmin, "host-admin"),
            (Capability::SerialDevices, "serial-devices"),
            (Capability::Gpu, "gpu"),
        ] {
            assert_eq!(c.label(), format!("capability.platform.meridian/{name}"));
        }
    }
}
