//! Unknown etcd flags are never fatal: a launcher that adds a flag must not stop the
//! control plane from booting.

#[derive(Debug, Default, PartialEq, Eq)]
pub struct EtcdArgs {
    pub data_dir: Option<String>,
    pub listen_client: Option<String>,
    pub listen_peer: Option<String>,
    pub advertise_client: Option<String>,
    pub advertise_peer: Option<String>,
    pub listen_client_http: Option<String>,
    pub watch_progress_notify_interval_secs: Option<u64>,
    pub max_request_bytes: Option<u64>,
    pub name: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub trusted_ca_file: Option<String>,
    pub client_cert_auth: bool,
    pub ignored: Vec<String>,
}

pub fn url_to_addr(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = rest.split('/').next()?;
    let (_, port) = hostport.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    Some(hostport.to_string())
}

/// At least 1: rounding a sub-second interval down to 0 would disable progress notifications.
pub fn parse_duration_secs(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult_div) = if let Some(n) = v.strip_suffix("ms") {
        (n, (1u64, 1000u64))
    } else if let Some(n) = v.strip_suffix('s') {
        (n, (1, 1))
    } else if let Some(n) = v.strip_suffix('m') {
        (n, (60, 1))
    } else if let Some(n) = v.strip_suffix('h') {
        (n, (3600, 1))
    } else {
        (v, (1, 1))
    };
    let n: u64 = num.parse().ok()?;
    let secs = n.saturating_mul(mult_div.0) / mult_div.1;
    Some(secs.max(1))
}

/// pflag never takes a boolean flag's value from the next argument.
const BOOLEAN_FLAGS: [&str; 4] = [
    "client-cert-auth",
    "auto-tls",
    "peer-auto-tls",
    "peer-client-cert-auth",
];

const INERT_FLAGS: [&str; 19] = [
    "initial-cluster",
    "initial-cluster-state",
    "initial-cluster-token",
    "election-timeout",
    "heartbeat-interval",
    "auto-compaction-mode",
    "auto-compaction-retention",
    "auto-tls",
    "peer-auto-tls",
    "peer-cert-file",
    "peer-key-file",
    "peer-trusted-ca-file",
    "peer-client-cert-auth",
    "tls-min-version",
    "feature-gates",
    "quota-backend-bytes",
    "logger",
    "log-level",
    "log-outputs",
];

fn first(list: &str) -> Option<&str> {
    list.split(',').next()
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> EtcdArgs {
    let mut out = EtcdArgs::default();
    let mut args = args.into_iter().peekable();
    while let Some(a) = args.next() {
        let Some(body) = a.strip_prefix("--") else {
            out.ignored.push(a);
            continue;
        };
        let joined;
        let (k, v) = match body.split_once('=') {
            Some((k, v)) => (k, v),
            None if !BOOLEAN_FLAGS.contains(&body)
                && args.peek().is_some_and(|n| !n.starts_with("--")) =>
            {
                joined = args.next().unwrap_or_default();
                (body, joined.as_str())
            }
            None => (body, "true"),
        };
        match k {
            "data-dir" => out.data_dir = Some(v.to_string()),
            "listen-client-urls" => out.listen_client = first(v).and_then(url_to_addr),
            "listen-peer-urls" => out.listen_peer = first(v).and_then(url_to_addr),
            "listen-client-http-urls" => out.listen_client_http = first(v).and_then(url_to_addr),
            "advertise-client-urls" => out.advertise_client = first(v).map(str::to_string),
            "initial-advertise-peer-urls" => out.advertise_peer = first(v).map(str::to_string),
            "watch-progress-notify-interval" => {
                out.watch_progress_notify_interval_secs = parse_duration_secs(v);
            }
            "max-request-bytes" => match v.parse() {
                Ok(bytes) => out.max_request_bytes = Some(bytes),
                Err(_) => out.ignored.push(a.clone()),
            },
            "name" => out.name = Some(v.to_string()),
            "cert-file" => out.cert_file = Some(v.to_string()),
            "key-file" => out.key_file = Some(v.to_string()),
            "trusted-ca-file" => out.trusted_ca_file = Some(v.to_string()),
            "client-cert-auth" => out.client_cert_auth = v == "true",
            k if INERT_FLAGS.contains(&k) => {}
            _ => out.ignored.push(a),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_talos_command_line() {
        let a = parse(argv(&[
            "--advertise-client-urls=https://10.51.0.1:2379",
            "--auto-compaction-mode=periodic",
            "--auto-compaction-retention=1h",
            "--auto-tls=false",
            "--cert-file=/system/secrets/etcd/server.crt",
            "--client-cert-auth=true",
            "--data-dir=/var/lib/etcd",
            "--election-timeout=500",
            "--feature-gates=InitialCorruptCheck=true",
            "--feature-gates=CompactHashCheck=true",
            "--heartbeat-interval=50",
            "--initial-advertise-peer-urls=https://10.51.0.1:2380",
            "--initial-cluster=node-1=https://10.51.0.1:2380",
            "--initial-cluster-state=new",
            "--key-file=/system/secrets/etcd/server.key",
            "--listen-client-http-urls=https://0.0.0.0:2383",
            "--listen-client-urls=https://0.0.0.0:2379",
            "--listen-peer-urls=https://0.0.0.0:2380",
            "--name=node-1",
            "--peer-auto-tls=false",
            "--peer-cert-file=/system/secrets/etcd/peer.crt",
            "--peer-client-cert-auth=true",
            "--peer-key-file=/system/secrets/etcd/peer.key",
            "--peer-trusted-ca-file=/system/secrets/etcd/ca.crt",
            "--tls-min-version=TLS1.3",
            "--trusted-ca-file=/system/secrets/etcd/ca.crt",
            "--watch-progress-notify-interval=5s",
        ]));
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            a,
            EtcdArgs {
                data_dir: s("/var/lib/etcd"),
                listen_client: s("0.0.0.0:2379"),
                listen_peer: s("0.0.0.0:2380"),
                advertise_client: s("https://10.51.0.1:2379"),
                advertise_peer: s("https://10.51.0.1:2380"),
                listen_client_http: s("0.0.0.0:2383"),
                watch_progress_notify_interval_secs: Some(5),
                max_request_bytes: None,
                name: s("node-1"),
                cert_file: s("/system/secrets/etcd/server.crt"),
                key_file: s("/system/secrets/etcd/server.key"),
                trusted_ca_file: s("/system/secrets/etcd/ca.crt"),
                client_cert_auth: true,
                ignored: vec![],
            }
        );
    }

    #[test]
    fn ignores_unknown_flags() {
        let a = parse(argv(&["--data-dir=/d", "--brand-new-flag=7", "stray"]));
        assert_eq!(a.data_dir.as_deref(), Some("/d"));
        assert_eq!(a.ignored, argv(&["--brand-new-flag=7", "stray"]));
    }

    #[test]
    fn takes_first_url() {
        let a = parse(argv(&[
            "--listen-client-urls=https://1.2.3.4:2379,https://5.6.7.8:2379",
            "--advertise-client-urls=https://1.2.3.4:2379,https://5.6.7.8:2379",
        ]));
        assert_eq!(a.listen_client.as_deref(), Some("1.2.3.4:2379"));
        assert_eq!(a.advertise_client.as_deref(), Some("https://1.2.3.4:2379"));
    }

    #[test]
    fn url_to_addr_needs_a_port() {
        for (url, want) in [
            ("https://1.2.3.4:2379", Some("1.2.3.4:2379")),
            ("https://1.2.3.4:2379/path", Some("1.2.3.4:2379")),
            ("1.2.3.4:2379", Some("1.2.3.4:2379")),
            ("https://1.2.3.4", None),
            ("https://[::1]:2379", Some("[::1]:2379")),
            ("https://[::1]", None),
            ("https://0.0.0.0:", None),
            ("unix:///tmp/x", None),
        ] {
            assert_eq!(url_to_addr(url).as_deref(), want, "{url}");
        }
    }

    #[test]
    fn durations_round_up_to_seconds() {
        for (v, want) in [
            ("5s", Some(5)),
            (" 5s ", Some(5)),
            ("5", Some(5)),
            ("2m", Some(120)),
            ("1h", Some(3600)),
            ("2500ms", Some(2)),
            ("500ms", Some(1)),
            ("0s", Some(1)),
            ("soon", None),
            ("", None),
        ] {
            assert_eq!(parse_duration_secs(v), want, "{v:?}");
        }
    }

    #[test]
    fn client_cert_auth_forms() {
        for (a, want) in [
            (argv(&["--client-cert-auth=true"]), true),
            (argv(&["--client-cert-auth=false"]), false),
            (argv(&["--client-cert-auth"]), true),
            (argv(&[]), false),
        ] {
            assert_eq!(parse(a.clone()).client_cert_auth, want, "{a:?}");
        }
    }

    #[test]
    fn separate_flag_values() {
        let a = parse(argv(&[
            "--data-dir",
            "/d",
            "--listen-client-urls",
            "https://0.0.0.0:2379",
            "--client-cert-auth",
            "--cert-file",
            "/c.crt",
            "--unknown",
            "--name",
            "n1",
        ]));
        assert_eq!(a.data_dir.as_deref(), Some("/d"));
        assert_eq!(a.listen_client.as_deref(), Some("0.0.0.0:2379"));
        assert_eq!(a.cert_file.as_deref(), Some("/c.crt"));
        assert_eq!(a.name.as_deref(), Some("n1"));
        assert!(a.client_cert_auth);
        assert_eq!(a.ignored, argv(&["--unknown"]));
    }

    #[test]
    fn max_request_bytes() {
        assert_eq!(
            parse(argv(&["--max-request-bytes=10485760"])).max_request_bytes,
            Some(10 << 20)
        );
        let bad = parse(argv(&["--max-request-bytes", "lots"]));
        assert_eq!(bad.max_request_bytes, None);
        assert_eq!(bad.ignored, argv(&["--max-request-bytes"]));
    }

    #[test]
    fn boolean_flag_takes_no_value() {
        let a = parse(argv(&["--client-cert-auth", "false"]));
        assert!(a.client_cert_auth);
        assert_eq!(a.ignored, argv(&["false"]));
    }
}
