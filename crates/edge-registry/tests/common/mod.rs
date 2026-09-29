#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use edge_registry::Digest;

pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";

pub fn tempdir() -> tempfile::TempDir {
    let base = std::env::var_os("HOME")
        .map(|h| Path::new(&h).join(".cache/meridian-edge-test-tmp"))
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

pub struct Blob {
    pub digest: Digest,
    pub bytes: Vec<u8>,
}

impl Blob {
    pub fn descriptor(&self, media_type: &str) -> serde_json::Value {
        serde_json::json!({
            "mediaType": media_type,
            "digest": self.digest.to_string(),
            "size": self.bytes.len(),
        })
    }
}

/// An OCI image layout being written, as `skopeo copy … oci:` leaves one.
pub struct Layout {
    pub dir: PathBuf,
    index: Vec<serde_json::Value>,
}

pub struct Image {
    pub manifest: Blob,
    pub config: Blob,
    pub layers: Vec<Blob>,
}

impl Layout {
    pub fn new(dir: &Path) -> Layout {
        std::fs::create_dir_all(dir.join("blobs/sha256")).unwrap();
        Layout {
            dir: dir.to_path_buf(),
            index: Vec::new(),
        }
    }

    pub fn blob(&self, bytes: impl Into<Vec<u8>>) -> Blob {
        let bytes = bytes.into();
        let digest = Digest::of(&bytes);
        std::fs::write(self.path(&digest), &bytes).unwrap();
        Blob { digest, bytes }
    }

    pub fn path(&self, digest: &Digest) -> PathBuf {
        self.dir.join("blobs/sha256").join(digest.hex())
    }

    pub fn image(&self, seed: &str, layers: usize) -> Image {
        let config = self.blob(format!(
            r#"{{"architecture":"amd64","os":"linux","config":{{"Cmd":["/{seed}"]}},"rootfs":{{"type":"layers","diff_ids":[]}}}}"#
        ));
        let layers: Vec<Blob> = (0..layers)
            .map(|i| self.blob(format!("{seed} layer {i} ").repeat(1000 + i)))
            .collect();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": config.descriptor("application/vnd.oci.image.config.v1+json"),
            "layers": layers.iter()
                .map(|l| l.descriptor("application/vnd.oci.image.layer.v1.tar+gzip"))
                .collect::<Vec<_>>(),
        });
        let manifest = self.blob(serde_json::to_vec_pretty(&manifest).unwrap());
        Image {
            manifest,
            config,
            layers,
        }
    }

    /// An index over `platforms`, of which only those in `held` are in the layout.
    pub fn index(&self, platforms: &[&Image], held: usize) -> Blob {
        let manifests: Vec<_> = platforms
            .iter()
            .enumerate()
            .map(|(i, img)| {
                let mut d = img.manifest.descriptor(MANIFEST);
                d["platform"] =
                    serde_json::json!({"os": "linux", "architecture": format!("arch{i}")});
                d
            })
            .collect();
        for img in &platforms[held..] {
            std::fs::remove_file(self.path(&img.manifest.digest)).unwrap();
        }
        self.blob(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": INDEX,
                "manifests": manifests,
            }))
            .unwrap(),
        )
    }

    pub fn add(&mut self, manifest: &Blob, media_type: &str, annotations: &[(&str, &str)]) {
        let mut d = manifest.descriptor(media_type);
        if !annotations.is_empty() {
            d["annotations"] = annotations
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::from(*v)))
                .collect::<serde_json::Map<_, _>>()
                .into();
        }
        self.index.push(d);
    }

    pub fn tag(&mut self, image: &Image, name: &str) {
        self.add(
            &image.manifest,
            MANIFEST,
            &[("org.opencontainers.image.ref.name", name)],
        );
    }

    pub fn write(&self) -> &Path {
        std::fs::write(
            self.dir.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": self.index,
        });
        std::fs::write(
            self.dir.join("index.json"),
            serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
        &self.dir
    }
}

pub struct Registry {
    child: Child,
    pub port: u16,
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Registry {
    /// Its upstream is a port nothing listens on.
    pub fn start(root: &Path) -> Registry {
        Registry::with_upstream(root, free_port())
    }

    pub fn with_upstream(root: &Path, upstream: u16) -> Registry {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_edge-registry"))
            .args(["--root".as_ref(), root.as_os_str()])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .args(["--upstream", &format!("127.0.0.1:{upstream}")])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut registry = Registry { child, port };
        let until = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            if let Ok(Some(status)) = registry.child.try_wait() {
                panic!("edge-registry exited: {status}");
            }
            assert!(Instant::now() < until, "edge-registry never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        registry
    }

    pub fn request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Response {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete response head");
        let head = String::from_utf8(raw[..split].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        Response {
            status,
            headers,
            body: raw[split + 4..].to_vec(),
        }
    }

    pub fn get(&self, path: &str) -> Response {
        self.request("GET", path, &[])
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A registry that answers each path with a canned response and records what
/// it was asked.
pub struct Stub {
    pub port: u16,
    pub seen: Arc<Mutex<Vec<String>>>,
}

pub struct Canned {
    pub status: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Stub {
    pub fn start(answers: HashMap<String, Canned>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let mut head = Vec::new();
                let mut b = [0u8];
                while !head.ends_with(b"\r\n\r\n") && conn.read(&mut b).is_ok_and(|n| n == 1) {
                    head.push(b[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let target = head.split(' ').nth(1).unwrap_or_default().to_string();
                log.lock().unwrap().push(head);
                let resp = match answers.get(&target) {
                    Some(c) => {
                        let mut r = format!("HTTP/1.1 {}\r\nConnection: close\r\n", c.status);
                        for (k, v) in &c.headers {
                            r.push_str(&format!("{k}: {v}\r\n"));
                        }
                        r.push_str(&format!("Content-Length: {}\r\n\r\n", c.body.len()));
                        [r.into_bytes(), c.body.clone()].concat()
                    }
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = conn.write_all(&resp);
            }
        });
        Stub { port, seen }
    }

    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}
