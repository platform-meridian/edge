use std::collections::HashMap;

use edge_cni_common::{AllowKey, AllowVal, PodVal};

use crate::netpol::{PolicyMaps, key_bytes};

#[derive(Default)]
pub(crate) struct Mem {
    pub pods: HashMap<u32, PodVal>,
    pub ips: HashMap<u32, u32>,
    pub allow: HashMap<(u32, [u8; 12]), (AllowKey, AllowVal)>,
    pub armed: bool,
    pub log: Vec<String>,
    pub fail_writes: bool,
}

impl Mem {
    fn write(&mut self, op: String) -> anyhow::Result<()> {
        if self.fail_writes {
            anyhow::bail!("{op}: E2BIG");
        }
        self.log.push(op);
        Ok(())
    }
}

impl PolicyMaps for Mem {
    fn dump_pods(&self) -> anyhow::Result<Vec<(u32, PodVal)>> {
        Ok(self.pods.iter().map(|(k, v)| (*k, *v)).collect())
    }
    fn dump_pod_ips(&self) -> anyhow::Result<Vec<(u32, u32)>> {
        Ok(self.ips.iter().map(|(k, v)| (*k, *v)).collect())
    }
    fn dump_allow(&self) -> anyhow::Result<Vec<(u32, AllowKey, AllowVal)>> {
        Ok(self
            .allow
            .iter()
            .map(|((b, _), (k, v))| (*b, *k, *v))
            .collect())
    }
    fn armed(&self) -> anyhow::Result<bool> {
        Ok(self.armed)
    }
    fn put_pod(&mut self, i: u32, v: &PodVal) -> anyhow::Result<()> {
        self.write("put_pod".into())?;
        self.pods.insert(i, *v);
        Ok(())
    }
    fn del_pod(&mut self, i: u32) -> anyhow::Result<()> {
        self.write("del_pod".into())?;
        self.pods.remove(&i);
        Ok(())
    }
    fn put_pod_ip(&mut self, i: u32, x: u32) -> anyhow::Result<()> {
        self.write("put_ip".into())?;
        self.ips.insert(i, x);
        Ok(())
    }
    fn del_pod_ip(&mut self, i: u32) -> anyhow::Result<()> {
        self.write("del_ip".into())?;
        self.ips.remove(&i);
        Ok(())
    }
    fn put_allow(&mut self, b: u32, k: &AllowKey, v: &AllowVal) -> anyhow::Result<()> {
        self.write("put_allow".into())?;
        self.allow.insert((b, key_bytes(k)), (*k, *v));
        Ok(())
    }
    fn del_allow(&mut self, b: u32, k: &AllowKey) -> anyhow::Result<()> {
        self.write("del_allow".into())?;
        self.allow.remove(&(b, key_bytes(k)));
        Ok(())
    }
    fn set_armed(&mut self, on: bool) -> anyhow::Result<()> {
        self.write(format!("armed={on}"))?;
        self.armed = on;
        Ok(())
    }
}
