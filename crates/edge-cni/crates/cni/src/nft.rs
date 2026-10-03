//! Netfilter rather than a BPF NAT: conntrack handles IP fragments, ICMP errors and
//! tuples a host socket already owns. Only off-node traffic reaches here: local
//! sockets are translated at connect().
//! ClientIP affinity hashes the source address, so it has no timeout.

use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, bail};
use rtnetlink::sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

pub const TABLE: &str = "edge-cni";
pub const CHAIN: &str = "postrouting";
pub const DNAT_CHAIN: &str = "prerouting";

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNETLINK_V0: u8 = 0;
const NFPROTO_IPV4: u8 = 2;

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;
const MSG_DONTWAIT: i32 = 0x40;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_FIB_DREG: u16 = 1;
const NFTA_FIB_RESULT: u16 = 2;
const NFTA_FIB_FLAGS: u16 = 3;
const NFTA_NG_DREG: u16 = 1;
const NFTA_NG_MODULUS: u16 = 2;
const NFTA_NG_TYPE: u16 = 3;
const NFTA_NG_OFFSET: u16 = 4;
const NFTA_HASH_SREG: u16 = 1;
const NFTA_HASH_DREG: u16 = 2;
const NFTA_HASH_LEN: u16 = 3;
const NFTA_HASH_MODULUS: u16 = 4;
const NFTA_HASH_SEED: u16 = 5;
const NFTA_HASH_OFFSET: u16 = 6;
const NFTA_HASH_TYPE: u16 = 7;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
const NFTA_NAT_FLAGS: u16 = 7;

const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_POST_ROUTING: u32 = 4;
const NF_IP_PRI_NAT_DST: i32 = -100;
const NF_IP_PRI_NAT_SRC: i32 = 100;
const NFT_REG_1: u32 = 1;
const NFT_REG_2: u32 = 2;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_META_L4PROTO: u32 = 16;
const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
const NFTA_FIB_F_DADDR: u32 = 2;
const RTN_LOCAL: u32 = 2;
const NFT_NG_RANDOM: u32 = 1;
const NFT_HASH_JENKINS: u32 = 0;
// Without a seed each rule draws its own, and the dump leaves it out.
const HASH_SEED: u32 = 0;
const NFT_NAT_DNAT: u32 = 1;
// The kernel sets these itself when the address and port registers are given.
const NF_NAT_RANGE_IMPLIED: u32 = 0x1 | 0x2;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const IPV4_SADDR_OFFSET: u32 = 12;
const IPV4_DADDR_OFFSET: u32 = 16;

// Decoded from the kernel's dump so presence is compared by meaning, not bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Payload { base: u32, offset: u32, len: u32 },
    Bitwise { len: u32, mask: Vec<u8> },
    Cmp { op: u32, data: Vec<u8> },
    Masq,
    Meta { key: u32 },
    Fib { result: u32, flags: u32 },
    Numgen { modulus: u32 },
    // jhash of the 4 bytes in register 1, scaled to 0..modulus.
    Hash { modulus: u32 },
    Immediate { reg: u32, data: Vec<u8> },
    Dnat,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub proto: u8,
    pub addr: Option<Ipv4Addr>,
    pub port: u16,
    pub backends: Vec<SocketAddrV4>,
    pub affinity: bool,
}

fn mask(prefix: u8) -> [u8; 4] {
    let m = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    m.to_be_bytes()
}

pub fn masquerade_rule(pod_net: Ipv4Addr, prefix: u8) -> Vec<Expr> {
    let m = mask(prefix);
    let net: Vec<u8> = pod_net.octets().iter().zip(m).map(|(a, m)| a & m).collect();
    let mut out = Vec::new();
    for (offset, op) in [
        (IPV4_SADDR_OFFSET, NFT_CMP_EQ),
        (IPV4_DADDR_OFFSET, NFT_CMP_NEQ),
    ] {
        out.push(Expr::Payload {
            base: NFT_PAYLOAD_NETWORK_HEADER,
            offset,
            len: 4,
        });
        out.push(Expr::Bitwise {
            len: 4,
            mask: m.to_vec(),
        });
        out.push(Expr::Cmp {
            op,
            data: net.clone(),
        });
    }
    out.push(Expr::Masq);
    out
}

fn cmp_eq(data: &[u8]) -> Expr {
    Expr::Cmp {
        op: NFT_CMP_EQ,
        data: data.to_vec(),
    }
}

// One rule per backend: rule i of n takes 1/(n-i) of what reaches it, so each
// backend gets 1/n. With affinity, rule i takes the sources that hash to i.
pub fn dnat_rules(f: &Forward) -> Vec<Vec<Expr>> {
    let destination = match f.addr {
        Some(addr) => vec![
            Expr::Payload {
                base: NFT_PAYLOAD_NETWORK_HEADER,
                offset: IPV4_DADDR_OFFSET,
                len: 4,
            },
            cmp_eq(&addr.octets()),
        ],
        None => vec![
            Expr::Fib {
                result: NFT_FIB_RESULT_ADDRTYPE,
                flags: NFTA_FIB_F_DADDR,
            },
            cmp_eq(&RTN_LOCAL.to_ne_bytes()),
        ],
    };
    let n = f.backends.len();
    f.backends
        .iter()
        .enumerate()
        .map(|(i, backend)| {
            let mut rule = destination.clone();
            rule.extend([
                Expr::Meta {
                    key: NFT_META_L4PROTO,
                },
                cmp_eq(&[f.proto]),
                Expr::Payload {
                    base: NFT_PAYLOAD_TRANSPORT_HEADER,
                    offset: 2,
                    len: 2,
                },
                cmp_eq(&f.port.to_be_bytes()),
            ]);
            let remaining = (n - i) as u32;
            if remaining > 1 && f.affinity {
                rule.extend([
                    Expr::Payload {
                        base: NFT_PAYLOAD_NETWORK_HEADER,
                        offset: IPV4_SADDR_OFFSET,
                        len: 4,
                    },
                    Expr::Hash { modulus: n as u32 },
                    cmp_eq(&(i as u32).to_ne_bytes()),
                ]);
            } else if remaining > 1 {
                rule.push(Expr::Numgen { modulus: remaining });
                rule.push(cmp_eq(&0u32.to_ne_bytes()));
            }
            rule.extend([
                Expr::Immediate {
                    reg: NFT_REG_1,
                    data: backend.ip().octets().to_vec(),
                },
                Expr::Immediate {
                    reg: NFT_REG_2,
                    data: backend.port().to_be_bytes().to_vec(),
                },
                Expr::Dnat,
            ]);
            rule
        })
        .collect()
}

// Addressed forwards first: a wildcard on the same port must not shadow them.
fn all_dnat_rules(forwards: &[Forward]) -> Vec<Vec<Expr>> {
    let (addressed, wildcard): (Vec<&Forward>, Vec<&Forward>) =
        forwards.iter().partition(|f| f.addr.is_some());
    addressed
        .into_iter()
        .chain(wildcard)
        .flat_map(dnat_rules)
        .collect()
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

fn attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    buf.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf.resize(buf.len() + pad4(payload.len()) - payload.len(), 0);
}

fn attr_str(buf: &mut Vec<u8>, ty: u16, s: &str) {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    attr(buf, ty, &v);
}

fn attr_u32_be(buf: &mut Vec<u8>, ty: u16, v: u32) {
    attr(buf, ty, &v.to_be_bytes());
}

fn nested(buf: &mut Vec<u8>, ty: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let start = buf.len();
    buf.extend_from_slice(&[0; 4]);
    f(buf);
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    buf[start + 2..start + 4].copy_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
}

fn data_value(buf: &mut Vec<u8>, ty: u16, value: &[u8]) {
    nested(buf, ty, |b| attr(b, NFTA_DATA_VALUE, value));
}

fn message(
    buf: &mut Vec<u8>,
    ty: u16,
    flags: u16,
    seq: u32,
    res_id: u16,
    f: impl FnOnce(&mut Vec<u8>),
) {
    let start = buf.len();
    buf.extend_from_slice(&[0; 16]);
    buf.push(NFPROTO_IPV4); // BATCH_* ignore the family
    buf.push(NFNETLINK_V0);
    buf.extend_from_slice(&res_id.to_be_bytes());
    f(buf);
    let len = (buf.len() - start) as u32;
    buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
    buf[start + 4..start + 6].copy_from_slice(&ty.to_ne_bytes());
    buf[start + 6..start + 8].copy_from_slice(&flags.to_ne_bytes());
    buf[start + 8..start + 12].copy_from_slice(&seq.to_ne_bytes());
}

fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

fn encode_expr(buf: &mut Vec<u8>, e: &Expr) {
    nested(buf, NFTA_LIST_ELEM, |b| match e {
        Expr::Payload { base, offset, len } => {
            attr_str(b, NFTA_EXPR_NAME, "payload");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_PAYLOAD_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_PAYLOAD_BASE, *base);
                attr_u32_be(b, NFTA_PAYLOAD_OFFSET, *offset);
                attr_u32_be(b, NFTA_PAYLOAD_LEN, *len);
            });
        }
        Expr::Bitwise { len, mask } => {
            attr_str(b, NFTA_EXPR_NAME, "bitwise");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_BITWISE_SREG, NFT_REG_1);
                attr_u32_be(b, NFTA_BITWISE_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_BITWISE_LEN, *len);
                data_value(b, NFTA_BITWISE_MASK, mask);
                data_value(b, NFTA_BITWISE_XOR, &vec![0; *len as usize]);
            });
        }
        Expr::Cmp { op, data } => {
            attr_str(b, NFTA_EXPR_NAME, "cmp");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_CMP_SREG, NFT_REG_1);
                attr_u32_be(b, NFTA_CMP_OP, *op);
                data_value(b, NFTA_CMP_DATA, data);
            });
        }
        Expr::Masq => attr_str(b, NFTA_EXPR_NAME, "masq"),
        Expr::Meta { key } => {
            attr_str(b, NFTA_EXPR_NAME, "meta");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_META_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_META_KEY, *key);
            });
        }
        Expr::Fib { result, flags } => {
            attr_str(b, NFTA_EXPR_NAME, "fib");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_FIB_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_FIB_RESULT, *result);
                attr_u32_be(b, NFTA_FIB_FLAGS, *flags);
            });
        }
        Expr::Numgen { modulus } => {
            attr_str(b, NFTA_EXPR_NAME, "numgen");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_NG_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_NG_MODULUS, *modulus);
                attr_u32_be(b, NFTA_NG_TYPE, NFT_NG_RANDOM);
            });
        }
        Expr::Hash { modulus } => {
            attr_str(b, NFTA_EXPR_NAME, "hash");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_HASH_SREG, NFT_REG_1);
                attr_u32_be(b, NFTA_HASH_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_HASH_LEN, 4);
                attr_u32_be(b, NFTA_HASH_MODULUS, *modulus);
                attr_u32_be(b, NFTA_HASH_SEED, HASH_SEED);
                attr_u32_be(b, NFTA_HASH_TYPE, NFT_HASH_JENKINS);
            });
        }
        Expr::Immediate { reg, data } => {
            attr_str(b, NFTA_EXPR_NAME, "immediate");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_IMMEDIATE_DREG, *reg);
                data_value(b, NFTA_IMMEDIATE_DATA, data);
            });
        }
        Expr::Dnat => {
            attr_str(b, NFTA_EXPR_NAME, "nat");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_NAT_TYPE, NFT_NAT_DNAT);
                attr_u32_be(b, NFTA_NAT_FAMILY, NFPROTO_IPV4 as u32);
                attr_u32_be(b, NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
                attr_u32_be(b, NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
            });
        }
        Expr::Other(name) => attr_str(b, NFTA_EXPR_NAME, name),
    });
}

fn batch(f: impl FnOnce(&mut Vec<u8>, &mut dyn FnMut() -> u32)) -> Vec<u8> {
    let mut b = Vec::new();
    let mut seq = 1;
    let mut next = move || {
        seq += 1;
        seq - 1
    };
    let first = next();
    message(
        &mut b,
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        first,
        NFNL_SUBSYS_NFTABLES,
        |_| {},
    );
    f(&mut b, &mut next);
    let last = next();
    message(
        &mut b,
        NFNL_MSG_BATCH_END,
        NLM_F_REQUEST,
        last,
        NFNL_SUBSYS_NFTABLES,
        |_| {},
    );
    b
}

const ACK_CREATE: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

// The NEWTABLE first makes the delete succeed when the table is absent.
fn replace_table(b: &mut Vec<u8>, next: &mut dyn FnMut() -> u32) {
    message(b, nft_type(NFT_MSG_NEWTABLE), ACK_CREATE, next(), 0, |b| {
        attr_str(b, NFTA_TABLE_NAME, TABLE)
    });
    message(
        b,
        nft_type(NFT_MSG_DELTABLE),
        NLM_F_REQUEST | NLM_F_ACK,
        next(),
        0,
        |b| attr_str(b, NFTA_TABLE_NAME, TABLE),
    );
}

fn new_chain(b: &mut Vec<u8>, next: &mut dyn FnMut() -> u32, name: &str, hook: u32, priority: i32) {
    message(b, nft_type(NFT_MSG_NEWCHAIN), ACK_CREATE, next(), 0, |b| {
        attr_str(b, NFTA_CHAIN_TABLE, TABLE);
        attr_str(b, NFTA_CHAIN_NAME, name);
        nested(b, NFTA_CHAIN_HOOK, |b| {
            attr_u32_be(b, NFTA_HOOK_HOOKNUM, hook);
            attr_u32_be(b, NFTA_HOOK_PRIORITY, priority as u32);
        });
        attr_str(b, NFTA_CHAIN_TYPE, "nat");
    });
}

fn new_rule(
    b: &mut Vec<u8>,
    next: &mut dyn FnMut() -> u32,
    flags: u16,
    chain: &str,
    exprs: &[Expr],
) {
    message(b, nft_type(NFT_MSG_NEWRULE), flags, next(), 0, |b| {
        attr_str(b, NFTA_RULE_TABLE, TABLE);
        attr_str(b, NFTA_RULE_CHAIN, chain);
        nested(b, NFTA_RULE_EXPRESSIONS, |b| {
            exprs.iter().for_each(|e| encode_expr(b, e))
        });
    });
}

// Forwarding rules ask for no ack: thousands of acks would overrun the socket
// buffer, and a refused message is reported either way.
pub fn install_batch(pod_net: Ipv4Addr, prefix: u8, forwards: &[Forward]) -> Vec<u8> {
    batch(|b, next| {
        replace_table(b, next);
        message(b, nft_type(NFT_MSG_NEWTABLE), ACK_CREATE, next(), 0, |b| {
            attr_str(b, NFTA_TABLE_NAME, TABLE)
        });
        new_chain(b, next, CHAIN, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC);
        new_rule(
            b,
            next,
            ACK_CREATE | NLM_F_APPEND,
            CHAIN,
            &masquerade_rule(pod_net, prefix),
        );
        new_chain(b, next, DNAT_CHAIN, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST);
        for rule in all_dnat_rules(forwards) {
            new_rule(
                b,
                next,
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
                DNAT_CHAIN,
                &rule,
            );
        }
    })
}

pub fn remove_batch() -> Vec<u8> {
    batch(replace_table)
}

pub fn remove() -> anyhow::Result<()> {
    let n = Nfnl::open()?;
    n.0.send(&remove_batch(), 0)
        .context("send the remove batch")?;
    check_acks(&n, 2)
}

pub fn installed() -> anyhow::Result<Found> {
    read_state(&Nfnl::open()?)
}

fn check_acks(n: &Nfnl, want: usize) -> anyhow::Result<()> {
    let mut acks = 0;
    for buf in n.drain()? {
        for (ty, payload) in split_messages(&buf) {
            if ty != NLMSG_ERROR {
                continue;
            }
            let errno = i32::from_ne_bytes(
                payload
                    .get(..4)
                    .context("short error message")?
                    .try_into()
                    .unwrap(),
            );
            if errno != 0 {
                bail!(
                    "nf_tables refused the ruleset: {} (is nf_tables / nf_nat in the kernel?)",
                    std::io::Error::from_raw_os_error(-errno)
                );
            }
            acks += 1;
        }
    }
    if acks < want {
        bail!("nf_tables acknowledged {acks} of {want} messages");
    }
    Ok(())
}

const INSTALL_ACKS: usize = 6;

fn dump_request(msg: u16, seq: u32) -> Vec<u8> {
    let mut b = Vec::new();
    message(
        &mut b,
        nft_type(msg),
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        0,
        |_| {},
    );
    b
}

fn attrs(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let ty = u16::from_ne_bytes([buf[2], buf[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            break;
        }
        out.push((ty, &buf[4..len]));
        buf = &buf[pad4(len).min(buf.len())..];
    }
    out
}

fn find<'a>(a: &[(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    a.iter().find(|(t, _)| *t == ty).map(|(_, p)| *p)
}

fn be32(p: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(p.get(..4)?.try_into().ok()?))
}

fn cstr(p: &[u8]) -> String {
    String::from_utf8_lossy(p.split(|b| *b == 0).next().unwrap_or(&[])).into_owned()
}

fn data(p: &[u8]) -> Option<Vec<u8>> {
    find(&attrs(p), NFTA_DATA_VALUE).map(|v| v.to_vec())
}

pub fn decode_exprs(list: &[u8]) -> Vec<Expr> {
    let mut out = Vec::new();
    for (ty, elem) in attrs(list) {
        if ty != NFTA_LIST_ELEM {
            continue;
        }
        let a = attrs(elem);
        let name = find(&a, NFTA_EXPR_NAME).map(cstr).unwrap_or_default();
        let d = find(&a, NFTA_EXPR_DATA).map(attrs).unwrap_or_default();
        let e = match name.as_str() {
            "payload" => match (
                find(&d, NFTA_PAYLOAD_BASE).and_then(be32),
                find(&d, NFTA_PAYLOAD_OFFSET).and_then(be32),
                find(&d, NFTA_PAYLOAD_LEN).and_then(be32),
                find(&d, NFTA_PAYLOAD_DREG).and_then(be32),
            ) {
                // A load into register 1; a payload set has no DREG.
                (Some(base), Some(offset), Some(len), Some(NFT_REG_1)) => {
                    Expr::Payload { base, offset, len }
                }
                _ => Expr::Other(name),
            },
            "bitwise" => match (
                find(&d, NFTA_BITWISE_LEN).and_then(be32),
                find(&d, NFTA_BITWISE_MASK).and_then(data),
                find(&d, NFTA_BITWISE_XOR).and_then(data),
                find(&d, NFTA_BITWISE_SREG).and_then(be32),
                find(&d, NFTA_BITWISE_DREG).and_then(be32),
            ) {
                (Some(len), Some(mask), Some(xor), Some(NFT_REG_1), Some(NFT_REG_1))
                    if xor.iter().all(|b| *b == 0) =>
                {
                    Expr::Bitwise { len, mask }
                }
                _ => Expr::Other(name),
            },
            "cmp" => match (
                find(&d, NFTA_CMP_OP).and_then(be32),
                find(&d, NFTA_CMP_DATA).and_then(data),
                find(&d, NFTA_CMP_SREG).and_then(be32),
            ) {
                (Some(op), Some(data), Some(NFT_REG_1)) => Expr::Cmp { op, data },
                _ => Expr::Other(name),
            },
            "masq" if d.is_empty() => Expr::Masq,
            "meta" => match (
                find(&d, NFTA_META_KEY).and_then(be32),
                find(&d, NFTA_META_DREG).and_then(be32),
            ) {
                (Some(key), Some(NFT_REG_1)) => Expr::Meta { key },
                _ => Expr::Other(name),
            },
            "fib" => match (
                find(&d, NFTA_FIB_RESULT).and_then(be32),
                find(&d, NFTA_FIB_FLAGS).and_then(be32),
                find(&d, NFTA_FIB_DREG).and_then(be32),
            ) {
                (Some(result), Some(flags), Some(NFT_REG_1)) => Expr::Fib { result, flags },
                _ => Expr::Other(name),
            },
            "numgen" => match (
                find(&d, NFTA_NG_MODULUS).and_then(be32),
                find(&d, NFTA_NG_TYPE).and_then(be32),
                find(&d, NFTA_NG_OFFSET).and_then(be32).unwrap_or(0),
                find(&d, NFTA_NG_DREG).and_then(be32),
            ) {
                (Some(modulus), Some(NFT_NG_RANDOM), 0, Some(NFT_REG_1)) => {
                    Expr::Numgen { modulus }
                }
                _ => Expr::Other(name),
            },
            "hash" if is_plain_jhash(&d) => match find(&d, NFTA_HASH_MODULUS).and_then(be32) {
                Some(modulus) => Expr::Hash { modulus },
                None => Expr::Other(name),
            },
            "immediate" => match (
                find(&d, NFTA_IMMEDIATE_DREG).and_then(be32),
                find(&d, NFTA_IMMEDIATE_DATA).and_then(data),
            ) {
                (Some(reg), Some(data)) => Expr::Immediate { reg, data },
                _ => Expr::Other(name),
            },
            "nat" if is_plain_dnat(&d) => Expr::Dnat,
            _ => Expr::Other(name),
        };
        out.push(e);
    }
    out
}

fn is_plain_jhash(d: &[(u16, &[u8])]) -> bool {
    let reg = |ty| find(d, ty).and_then(be32);
    reg(NFTA_HASH_TYPE) == Some(NFT_HASH_JENKINS)
        && reg(NFTA_HASH_SREG) == Some(NFT_REG_1)
        && reg(NFTA_HASH_DREG) == Some(NFT_REG_1)
        && reg(NFTA_HASH_LEN) == Some(4)
        && reg(NFTA_HASH_SEED) == Some(HASH_SEED)
        && reg(NFTA_HASH_OFFSET).unwrap_or(0) == 0
}

fn is_plain_dnat(d: &[(u16, &[u8])]) -> bool {
    let reg = |ty| find(d, ty).and_then(be32);
    reg(NFTA_NAT_TYPE) == Some(NFT_NAT_DNAT)
        && reg(NFTA_NAT_FAMILY) == Some(NFPROTO_IPV4 as u32)
        && reg(NFTA_NAT_REG_ADDR_MIN) == Some(NFT_REG_1)
        && matches!(reg(NFTA_NAT_REG_ADDR_MAX), None | Some(NFT_REG_1))
        && reg(NFTA_NAT_REG_PROTO_MIN) == Some(NFT_REG_2)
        && matches!(reg(NFTA_NAT_REG_PROTO_MAX), None | Some(NFT_REG_2))
        && reg(NFTA_NAT_FLAGS).unwrap_or(0) & !NF_NAT_RANGE_IMPLIED == 0
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    // (name, hooknum, priority, type)
    pub chains: Vec<(String, u32, i32, String)>,
    pub rules: Vec<(String, Vec<Expr>)>,
}

pub fn split_messages(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= 16 {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes([buf[4], buf[5]]);
        if len < 16 || len > buf.len() {
            break;
        }
        out.push((ty, &buf[16..len]));
        buf = &buf[pad4(len).min(buf.len())..];
    }
    out
}

// Takes messages without their nlmsghdr.
pub fn fold_dump(chains: &[Vec<u8>], rules: &[Vec<u8>]) -> Found {
    let mut f = Found::default();
    for m in chains {
        let a = attrs(m.get(4..).unwrap_or(&[])); // skip nfgenmsg
        if find(&a, NFTA_CHAIN_TABLE).map(cstr).as_deref() != Some(TABLE) {
            continue;
        }
        let name = find(&a, NFTA_CHAIN_NAME).map(cstr).unwrap_or_default();
        let hook = find(&a, NFTA_CHAIN_HOOK).map(attrs).unwrap_or_default();
        let num = find(&hook, NFTA_HOOK_HOOKNUM)
            .and_then(be32)
            .unwrap_or(u32::MAX);
        let prio = find(&hook, NFTA_HOOK_PRIORITY)
            .and_then(be32)
            .map_or(i32::MIN, |p| p as i32);
        let ty = find(&a, NFTA_CHAIN_TYPE).map(cstr).unwrap_or_default();
        f.chains.push((name, num, prio, ty));
    }
    for m in rules {
        let a = attrs(m.get(4..).unwrap_or(&[]));
        if find(&a, NFTA_RULE_TABLE).map(cstr).as_deref() != Some(TABLE) {
            continue;
        }
        let chain = find(&a, NFTA_RULE_CHAIN).map(cstr).unwrap_or_default();
        let exprs = find(&a, NFTA_RULE_EXPRESSIONS)
            .map(decode_exprs)
            .unwrap_or_default();
        f.rules.push((chain, exprs));
    }
    f
}

fn masquerade_chain() -> (String, u32, i32, String) {
    (
        CHAIN.to_string(),
        NF_INET_POST_ROUTING,
        NF_IP_PRI_NAT_SRC,
        "nat".to_string(),
    )
}

pub fn expected(pod_net: Ipv4Addr, prefix: u8, forwards: &[Forward]) -> Found {
    Found {
        chains: vec![
            masquerade_chain(),
            (
                DNAT_CHAIN.to_string(),
                NF_INET_PRE_ROUTING,
                NF_IP_PRI_NAT_DST,
                "nat".to_string(),
            ),
        ],
        rules: std::iter::once((CHAIN.to_string(), masquerade_rule(pod_net, prefix)))
            .chain(
                all_dnat_rules(forwards)
                    .into_iter()
                    .map(|r| (DNAT_CHAIN.to_string(), r)),
            )
            .collect(),
    }
}

pub fn matches(found: &Found, pod_net: Ipv4Addr, prefix: u8, forwards: &[Forward]) -> bool {
    *found == expected(pod_net, prefix, forwards)
}

pub fn masquerade_intact(found: &Found, pod_net: Ipv4Addr, prefix: u8) -> bool {
    let masquerade: Vec<&Vec<Expr>> = found
        .rules
        .iter()
        .filter(|(chain, _)| chain == CHAIN)
        .map(|(_, rule)| rule)
        .collect();
    found
        .chains
        .iter()
        .filter(|c| c.0 == CHAIN)
        .eq([&masquerade_chain()])
        && masquerade == [&masquerade_rule(pod_net, prefix)]
}

struct Nfnl(Socket);

impl Nfnl {
    fn open() -> anyhow::Result<Self> {
        let mut s = Socket::new(NETLINK_NETFILTER).context("open a NETLINK_NETFILTER socket")?;
        s.bind_auto().context("bind the netlink socket")?;
        s.connect(&SocketAddr::new(0, 0))
            .context("connect to the kernel")?;
        Ok(Self(s))
    }

    // The kernel answers before `send` returns, so this never waits.
    fn drain(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            let mut buf = Vec::with_capacity(64 * 1024);
            match self.0.recv(&mut buf, MSG_DONTWAIT) {
                Ok(0) => break,
                Ok(_) => out.push(buf),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("read the netlink reply"),
            }
        }
        Ok(out)
    }

    // An error reply (ENOENT) means nothing is there.
    fn dump(&self, msg: u16) -> anyhow::Result<Vec<Vec<u8>>> {
        self.0
            .send(&dump_request(msg, 1), 0)
            .context("send the dump request")?;
        let mut out = Vec::new();
        for buf in self.drain()? {
            for (ty, payload) in split_messages(&buf) {
                match ty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => return Ok(out),
                    t if t == nft_type(msg_reply(msg)) => out.push(payload.to_vec()),
                    _ => {}
                }
            }
        }
        Ok(out)
    }
}

fn msg_reply(get: u16) -> u16 {
    match get {
        NFT_MSG_GETCHAIN => NFT_MSG_NEWCHAIN,
        _ => NFT_MSG_NEWRULE,
    }
}

fn read_state(n: &Nfnl) -> anyhow::Result<Found> {
    let chains = n.dump(NFT_MSG_GETCHAIN)?;
    let rules = n.dump(NFT_MSG_GETRULE)?;
    Ok(fold_dump(&chains, &rules))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Present,
    Installed,
}

fn install(n: &Nfnl, pod_net: Ipv4Addr, prefix: u8, forwards: &[Forward]) -> anyhow::Result<()> {
    n.0.send(&install_batch(pod_net, prefix, forwards), 0)
        .context("send the install batch")?;
    check_acks(n, INSTALL_ACKS)
}

pub fn ensure(
    pod_net: Ipv4Addr,
    prefix: u8,
    forwards: Option<&[Forward]>,
) -> anyhow::Result<Outcome> {
    let n = Nfnl::open()?;
    let found = read_state(&n)?;
    let forwards = match forwards {
        Some(f) => f,
        None if masquerade_intact(&found, pod_net, prefix) => return Ok(Outcome::Present),
        None => &[],
    };
    if matches(&found, pod_net, prefix, forwards) {
        return Ok(Outcome::Present);
    }
    match install(&n, pod_net, prefix, forwards) {
        Ok(()) => Ok(Outcome::Installed),
        // A refused batch changes nothing; egress must not wait on port forwarding.
        Err(e) if !forwards.is_empty() => {
            if !masquerade_intact(&read_state(&n)?, pod_net, prefix) {
                install(&n, pod_net, prefix, &[])?;
            }
            Err(e.context("install the node and host port forwarding"))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Ipv4Addr {
        Ipv4Addr::new(10, 244, 0, 0)
    }

    #[test]
    fn rule_matches_saddr_not_daddr() {
        let r = masquerade_rule(net(), 24);
        assert_eq!(r.len(), 7);
        assert_eq!(
            r[0],
            Expr::Payload {
                base: 1,
                offset: 12,
                len: 4
            }
        );
        assert_eq!(
            r[1],
            Expr::Bitwise {
                len: 4,
                mask: vec![255, 255, 255, 0]
            }
        );
        assert_eq!(
            r[2],
            Expr::Cmp {
                op: NFT_CMP_EQ,
                data: vec![10, 244, 0, 0]
            }
        );
        assert_eq!(
            r[3],
            Expr::Payload {
                base: 1,
                offset: 16,
                len: 4
            }
        );
        assert_eq!(
            r[5],
            Expr::Cmp {
                op: NFT_CMP_NEQ,
                data: vec![10, 244, 0, 0]
            }
        );
        assert_eq!(r[6], Expr::Masq);
    }

    #[test]
    fn cidr_is_masked() {
        assert_eq!(
            masquerade_rule(Ipv4Addr::new(10, 244, 0, 77), 24),
            masquerade_rule(net(), 24)
        );
    }

    #[test]
    fn mask_edges() {
        assert_eq!(mask(0), [0, 0, 0, 0]);
        assert_eq!(mask(8), [255, 0, 0, 0]);
        assert_eq!(mask(20), [255, 255, 240, 0]);
        assert_eq!(mask(32), [255, 255, 255, 255]);
    }

    #[test]
    fn rule_round_trips() {
        let mut list = Vec::new();
        let rule = masquerade_rule(net(), 16);
        for e in &rule {
            encode_expr(&mut list, e);
        }
        assert_eq!(decode_exprs(&list), rule);
    }

    #[test]
    fn different_cidr_differs() {
        let mut list = Vec::new();
        for e in &masquerade_rule(net(), 24) {
            encode_expr(&mut list, e);
        }
        assert_ne!(decode_exprs(&list), masquerade_rule(net(), 16));
        assert_ne!(
            decode_exprs(&list),
            masquerade_rule(Ipv4Addr::new(10, 245, 0, 0), 24)
        );
    }

    #[test]
    fn flagged_masq_is_foreign() {
        let mut list = Vec::new();
        nested(&mut list, NFTA_LIST_ELEM, |b| {
            attr_str(b, NFTA_EXPR_NAME, "masq");
            nested(b, NFTA_EXPR_DATA, |b| attr_u32_be(b, 1, 4));
        });
        assert_eq!(decode_exprs(&list), vec![Expr::Other("masq".into())]);
    }

    fn forward(addr: Option<[u8; 4]>, backends: u8) -> Forward {
        Forward {
            proto: 6,
            addr: addr.map(Ipv4Addr::from),
            port: 30080,
            backends: (1..=backends)
                .map(|i| SocketAddrV4::new(Ipv4Addr::new(10, 244, 0, i), 8080))
                .collect(),
            affinity: false,
        }
    }

    #[test]
    fn dnat_rules_split_evenly() {
        let rules = dnat_rules(&forward(None, 3));
        assert_eq!(rules.len(), 3);
        let moduli: Vec<Option<u32>> = rules
            .iter()
            .map(|r| {
                r.iter().find_map(|e| match e {
                    Expr::Numgen { modulus } => Some(*modulus),
                    _ => None,
                })
            })
            .collect();
        assert_eq!(
            moduli,
            [Some(3), Some(2), None],
            "the last rule takes the rest"
        );
        for (i, rule) in rules.iter().enumerate() {
            assert_eq!(
                rule[rule.len() - 3..],
                [
                    Expr::Immediate {
                        reg: NFT_REG_1,
                        data: vec![10, 244, 0, i as u8 + 1]
                    },
                    Expr::Immediate {
                        reg: NFT_REG_2,
                        data: 8080u16.to_be_bytes().to_vec()
                    },
                    Expr::Dnat,
                ]
            );
        }
        assert_eq!(
            rules[0][..6],
            [
                Expr::Fib {
                    result: NFT_FIB_RESULT_ADDRTYPE,
                    flags: NFTA_FIB_F_DADDR
                },
                cmp_eq(&RTN_LOCAL.to_ne_bytes()),
                Expr::Meta {
                    key: NFT_META_L4PROTO
                },
                cmp_eq(&[6]),
                Expr::Payload {
                    base: NFT_PAYLOAD_TRANSPORT_HEADER,
                    offset: 2,
                    len: 2
                },
                cmp_eq(&30080u16.to_be_bytes()),
            ]
        );
        assert!(dnat_rules(&forward(None, 0)).is_empty());
    }

    #[test]
    fn addressed_forward_matches_daddr() {
        let rule = &dnat_rules(&forward(Some([10, 70, 0, 1]), 1))[0];
        assert_eq!(
            rule[..2],
            [
                Expr::Payload {
                    base: NFT_PAYLOAD_NETWORK_HEADER,
                    offset: IPV4_DADDR_OFFSET,
                    len: 4
                },
                cmp_eq(&[10, 70, 0, 1]),
            ]
        );
    }

    #[test]
    fn addressed_forwards_first() {
        let rules = all_dnat_rules(&[forward(None, 1), forward(Some([10, 70, 0, 1]), 1)]);
        assert!(matches!(rules[0][0], Expr::Payload { .. }), "{rules:?}");
        assert!(matches!(rules[1][0], Expr::Fib { .. }), "{rules:?}");
    }

    fn sticky(backends: u8) -> Forward {
        Forward {
            affinity: true,
            ..forward(None, backends)
        }
    }

    #[test]
    fn affinity_hashes_the_source() {
        let rules = dnat_rules(&sticky(3));
        assert_eq!(rules.len(), 3);
        for (i, rule) in rules.iter().enumerate().take(2) {
            assert_eq!(
                rule[6..9],
                [
                    Expr::Payload {
                        base: NFT_PAYLOAD_NETWORK_HEADER,
                        offset: IPV4_SADDR_OFFSET,
                        len: 4
                    },
                    Expr::Hash { modulus: 3 },
                    cmp_eq(&(i as u32).to_ne_bytes()),
                ],
                "rule {i}"
            );
            assert_eq!(rule.len(), 12);
        }
        assert_eq!(rules[2].len(), 9, "the last rule takes the rest");
        let random = dnat_rules(&forward(None, 3));
        for (r, plain) in rules.iter().zip(&random) {
            assert_eq!(r[..6], plain[..6], "same match");
            assert_eq!(r[r.len() - 3..], plain[plain.len() - 3..], "same backend");
        }
        assert!(
            rules
                .iter()
                .flatten()
                .all(|e| !matches!(e, Expr::Numgen { .. })),
            "{rules:?}"
        );
        assert_eq!(dnat_rules(&sticky(1)), dnat_rules(&forward(None, 1)));
    }

    // NFTA_HASH_* from linux/netfilter/nf_tables.h, as libnftnl lays them out.
    #[test]
    fn hash_wire_layout() {
        let mut got = Vec::new();
        encode_expr(&mut got, &Expr::Hash { modulus: 3 });
        let u32_attr = |ty: u16, v: u32| {
            let mut a = 8u16.to_ne_bytes().to_vec();
            a.extend(ty.to_ne_bytes());
            a.extend(v.to_be_bytes());
            a
        };
        let data: Vec<u8> = [(1, 1), (2, 1), (3, 4), (4, 3), (5, 0), (7, 0)]
            .into_iter()
            .flat_map(|(ty, v)| u32_attr(ty, v))
            .collect();
        let mut want = 9u16.to_ne_bytes().to_vec();
        want.extend(1u16.to_ne_bytes());
        want.extend(b"hash\0\0\0\0");
        want.extend((4 + data.len() as u16).to_ne_bytes());
        want.extend((2u16 | 0x8000).to_ne_bytes());
        want.extend(data);
        let mut elem = (4 + want.len() as u16).to_ne_bytes().to_vec();
        elem.extend((1u16 | 0x8000).to_ne_bytes());
        elem.extend(want);
        assert_eq!(got, elem);
        assert_eq!(decode_exprs(&got), [Expr::Hash { modulus: 3 }]);
    }

    #[test]
    fn unlike_hash_is_foreign() {
        let hash = |attrs: &[(u16, u32)]| {
            let mut list = Vec::new();
            nested(&mut list, NFTA_LIST_ELEM, |b| {
                attr_str(b, NFTA_EXPR_NAME, "hash");
                nested(b, NFTA_EXPR_DATA, |b| {
                    attrs.iter().for_each(|(ty, v)| attr_u32_be(b, *ty, *v))
                });
            });
            decode_exprs(&list)
        };
        let ours = [
            (NFTA_HASH_SREG, NFT_REG_1),
            (NFTA_HASH_DREG, NFT_REG_1),
            (NFTA_HASH_LEN, 4),
            (NFTA_HASH_MODULUS, 2),
            (NFTA_HASH_SEED, HASH_SEED),
            (NFTA_HASH_TYPE, NFT_HASH_JENKINS),
        ];
        assert_eq!(hash(&ours), [Expr::Hash { modulus: 2 }]);
        assert_eq!(
            hash(&[ours.as_slice(), &[(NFTA_HASH_OFFSET, 0)]].concat()),
            [Expr::Hash { modulus: 2 }]
        );
        let foreign = |at: usize, v: u32| {
            let mut a = ours;
            a[at].1 = v;
            hash(&a)
        };
        let other = [Expr::Other("hash".into())];
        assert_eq!(foreign(0, NFT_REG_2), other, "sreg");
        assert_eq!(foreign(1, NFT_REG_2), other, "dreg");
        assert_eq!(foreign(2, 16), other, "len");
        assert_eq!(foreign(4, 1), other, "seed");
        assert_eq!(foreign(5, 1), other, "symhash");
        assert_eq!(hash(&ours[..4]), other, "random seed");
        assert_eq!(
            hash(&[&ours[..3], &ours[4..]].concat()),
            other,
            "no modulus"
        );
        assert_eq!(hash(&ours[..5]), other, "no type");
        assert_eq!(
            hash(&[ours.as_slice(), &[(NFTA_HASH_OFFSET, 1)]].concat()),
            other,
            "offset"
        );
    }

    #[test]
    fn affinity_change_is_drift() {
        let installed = fold_dump(
            &[chain_msg(CHAIN, 4, 100, "nat"), dnat_chain()],
            &std::iter::once(rule_msg(CHAIN, &masquerade_rule(net(), 24)))
                .chain(
                    dnat_rules(&sticky(2))
                        .iter()
                        .map(|r| rule_msg(DNAT_CHAIN, r)),
                )
                .collect::<Vec<_>>(),
        );
        assert!(matches(&installed, net(), 24, &[sticky(2)]));
        assert!(!matches(&installed, net(), 24, &[forward(None, 2)]));
        assert!(!matches(&installed, net(), 24, &[sticky(3)]));
    }

    #[test]
    fn dnat_rules_round_trip() {
        for rule in all_dnat_rules(&[
            forward(None, 2),
            forward(Some([10, 70, 0, 1]), 1),
            sticky(3),
        ]) {
            let mut list = Vec::new();
            rule.iter().for_each(|e| encode_expr(&mut list, e));
            assert_eq!(decode_exprs(&list), rule);
        }
    }

    #[test]
    fn nat_with_extra_flags_is_foreign() {
        let nat = |flags: u32| {
            let mut list = Vec::new();
            nested(&mut list, NFTA_LIST_ELEM, |b| {
                attr_str(b, NFTA_EXPR_NAME, "nat");
                nested(b, NFTA_EXPR_DATA, |b| {
                    attr_u32_be(b, NFTA_NAT_TYPE, NFT_NAT_DNAT);
                    attr_u32_be(b, NFTA_NAT_FAMILY, NFPROTO_IPV4 as u32);
                    attr_u32_be(b, NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
                    attr_u32_be(b, NFTA_NAT_REG_ADDR_MAX, NFT_REG_1);
                    attr_u32_be(b, NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
                    attr_u32_be(b, NFTA_NAT_REG_PROTO_MAX, NFT_REG_2);
                    attr_u32_be(b, NFTA_NAT_FLAGS, flags);
                });
            });
            decode_exprs(&list)
        };
        assert_eq!(nat(NF_NAT_RANGE_IMPLIED), [Expr::Dnat]);
        assert_eq!(nat(0x4), [Expr::Other("nat".into())], "random port");
    }

    #[test]
    fn install_batch_well_formed() {
        let b = install_batch(net(), 24, &[forward(None, 2)]);
        let msgs = split_messages(&b);
        let types: Vec<u16> = msgs.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            types,
            vec![
                NFNL_MSG_BATCH_BEGIN,
                nft_type(NFT_MSG_NEWTABLE),
                nft_type(NFT_MSG_DELTABLE),
                nft_type(NFT_MSG_NEWTABLE),
                nft_type(NFT_MSG_NEWCHAIN),
                nft_type(NFT_MSG_NEWRULE),
                nft_type(NFT_MSG_NEWCHAIN),
                nft_type(NFT_MSG_NEWRULE),
                nft_type(NFT_MSG_NEWRULE),
                NFNL_MSG_BATCH_END,
            ]
        );
        assert_eq!(b.len() % 4, 0);
        // begin carries the subsystem in res_id, network order
        assert_eq!(&msgs[0].1[2..4], &NFNL_SUBSYS_NFTABLES.to_be_bytes());
        let mut n = 0;
        let mut rest = &b[..];
        while rest.len() >= 16 {
            let len = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
            let flags = u16::from_ne_bytes([rest[6], rest[7]]);
            if flags & NLM_F_ACK != 0 {
                n += 1;
            }
            rest = &rest[pad4(len)..];
        }
        assert_eq!(n, INSTALL_ACKS);
    }

    #[test]
    fn rule_message_contents() {
        let b = install_batch(net(), 24, &[]);
        let msgs = split_messages(&b);
        let rule = &msgs[5].1;
        let a = attrs(&rule[4..]);
        assert_eq!(find(&a, NFTA_RULE_TABLE).map(cstr).as_deref(), Some(TABLE));
        assert_eq!(find(&a, NFTA_RULE_CHAIN).map(cstr).as_deref(), Some(CHAIN));
        assert_eq!(
            decode_exprs(find(&a, NFTA_RULE_EXPRESSIONS).unwrap()),
            masquerade_rule(net(), 24)
        );
    }

    fn chain_msg(name: &str, hook: u32, prio: i32, ty: &str) -> Vec<u8> {
        let mut m = vec![NFPROTO_IPV4, 0, 0, 0];
        attr_str(&mut m, NFTA_CHAIN_TABLE, TABLE);
        attr_str(&mut m, NFTA_CHAIN_NAME, name);
        nested(&mut m, NFTA_CHAIN_HOOK, |b| {
            attr_u32_be(b, NFTA_HOOK_HOOKNUM, hook);
            attr_u32_be(b, NFTA_HOOK_PRIORITY, prio as u32);
        });
        attr_str(&mut m, NFTA_CHAIN_TYPE, ty);
        m
    }

    fn rule_msg(chain: &str, exprs: &[Expr]) -> Vec<u8> {
        let mut m = vec![NFPROTO_IPV4, 0, 0, 0];
        attr_str(&mut m, NFTA_RULE_TABLE, TABLE);
        attr_str(&mut m, NFTA_RULE_CHAIN, chain);
        nested(&mut m, NFTA_RULE_EXPRESSIONS, |b| {
            exprs.iter().for_each(|e| encode_expr(b, e))
        });
        m
    }

    fn dnat_chain() -> Vec<u8> {
        chain_msg(DNAT_CHAIN, 0, -100, "nat")
    }

    fn good() -> Found {
        fold_dump(
            &[chain_msg(CHAIN, 4, 100, "nat"), dnat_chain()],
            &[rule_msg(CHAIN, &masquerade_rule(net(), 24))],
        )
    }

    #[test]
    fn installed_rule_matches() {
        assert!(matches(&good(), net(), 24, &[]));
        assert!(masquerade_intact(&good(), net(), 24));
    }

    #[test]
    fn any_deviation_mismatches() {
        assert!(!masquerade_intact(&Found::default(), net(), 24), "wiped");
        assert!(
            !masquerade_intact(&fold_dump(&[], &[]), net(), 24),
            "chain gone"
        );
        assert!(!masquerade_intact(&good(), net(), 16), "stale prefix");
        assert!(
            !masquerade_intact(&good(), Ipv4Addr::new(10, 245, 0, 0), 24),
            "stale network"
        );
        for (h, p, t) in [(3, 100, "nat"), (4, 0, "nat"), (4, 100, "filter")] {
            let f = fold_dump(
                &[chain_msg(CHAIN, h, p, t)],
                &[rule_msg(CHAIN, &masquerade_rule(net(), 24))],
            );
            assert!(!masquerade_intact(&f, net(), 24), "{h} {p} {t}");
        }
        assert!(
            !masquerade_intact(
                &fold_dump(&[chain_msg(CHAIN, 4, 100, "nat")], &[]),
                net(),
                24
            ),
            "rule missing"
        );
        let r = rule_msg(CHAIN, &masquerade_rule(net(), 24));
        assert!(
            !masquerade_intact(
                &fold_dump(&[chain_msg(CHAIN, 4, 100, "nat")], &[r.clone(), r]),
                net(),
                24
            ),
            "duplicated rule"
        );
        let extra = rule_msg(CHAIN, &[Expr::Other("counter".into())]);
        let r = rule_msg(CHAIN, &masquerade_rule(net(), 24));
        assert!(
            !masquerade_intact(
                &fold_dump(&[chain_msg(CHAIN, 4, 100, "nat")], &[r, extra]),
                net(),
                24
            ),
            "extra rule"
        );
        let f = fold_dump(
            &[
                chain_msg(CHAIN, 4, 100, "nat"),
                dnat_chain(),
                chain_msg("other", 4, 100, "nat"),
            ],
            &[rule_msg(CHAIN, &masquerade_rule(net(), 24))],
        );
        assert!(!matches(&f, net(), 24, &[]), "extra chain");
        assert!(masquerade_intact(&f, net(), 24));
        assert!(
            !matches(&good(), net(), 24, &[forward(None, 1)]),
            "forward missing"
        );
        let stale = fold_dump(
            &[chain_msg(CHAIN, 4, 100, "nat"), dnat_chain()],
            &[
                rule_msg(CHAIN, &masquerade_rule(net(), 24)),
                rule_msg(DNAT_CHAIN, &dnat_rules(&forward(None, 1))[0]),
            ],
        );
        assert!(matches(&stale, net(), 24, &[forward(None, 1)]));
        assert!(!matches(&stale, net(), 24, &[]), "forward removed");
        assert!(masquerade_intact(&stale, net(), 24));
    }

    #[test]
    fn other_tables_ignored() {
        let mut foreign = vec![NFPROTO_IPV4, 0, 0, 0];
        attr_str(&mut foreign, NFTA_CHAIN_TABLE, "kube-proxy");
        attr_str(&mut foreign, NFTA_CHAIN_NAME, "postrouting");
        let f = fold_dump(
            &[chain_msg(CHAIN, 4, 100, "nat"), dnat_chain(), foreign],
            &[rule_msg(CHAIN, &masquerade_rule(net(), 24))],
        );
        assert!(matches(&f, net(), 24, &[]));
    }

    #[test]
    fn xor_bitwise_is_foreign() {
        let mut list = Vec::new();
        nested(&mut list, NFTA_LIST_ELEM, |b| {
            attr_str(b, NFTA_EXPR_NAME, "bitwise");
            nested(b, NFTA_EXPR_DATA, |b| {
                attr_u32_be(b, NFTA_BITWISE_SREG, NFT_REG_1);
                attr_u32_be(b, NFTA_BITWISE_DREG, NFT_REG_1);
                attr_u32_be(b, NFTA_BITWISE_LEN, 4);
                data_value(b, NFTA_BITWISE_MASK, &[255, 255, 255, 0]);
                data_value(b, NFTA_BITWISE_XOR, &[0, 0, 0, 1]);
            });
        });
        assert_eq!(decode_exprs(&list), vec![Expr::Other("bitwise".into())]);
    }

    #[test]
    fn empty_attrs_keep_parsing() {
        let mut a = Vec::new();
        attr(&mut a, 7, &[]);
        attr_u32_be(&mut a, 9, 42);
        assert_eq!(attrs(&a), vec![(7, &[][..]), (9, &42u32.to_be_bytes()[..])]);

        let mut m = Vec::new();
        m.extend_from_slice(&16u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        message(&mut m, NLMSG_ERROR, 0, 2, 0, |_| {});
        let types: Vec<u16> = split_messages(&m).iter().map(|(t, _)| *t).collect();
        assert_eq!(types, [NLMSG_DONE, NLMSG_ERROR]);

        let mut long = m.clone();
        long[0..4].copy_from_slice(&1000u32.to_ne_bytes());
        assert!(split_messages(&long).is_empty(), "a length past the buffer");
    }

    #[test]
    fn garbage_decodes_to_nothing() {
        assert!(decode_exprs(&[1, 2, 3]).is_empty());
        assert!(decode_exprs(&[0xff, 0xff, 0, 0, 0, 0, 0, 0]).is_empty());
        assert!(split_messages(&[0; 5]).is_empty());
        assert_eq!(fold_dump(&[vec![1]], &[vec![]]), Found::default());
    }
}
