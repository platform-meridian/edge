//! PE32+ images: their sections, rebuilt with sections appended, and their
//! Authenticode digest and signature.

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

const SECTION_HEADER: usize = 40;
const CNT_INITIALIZED_DATA: u32 = 0x40;
const MEM_READ: u32 = 0x4000_0000;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

pub struct Pe<'a> {
    pub data: &'a [u8],
    pe_offset: usize,
    optional: usize,
    optional_size: usize,
    pub sections: Vec<Section>,
}

fn u16_at(b: &[u8], at: usize) -> anyhow::Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2).context("PE truncated")?.try_into()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4).context("PE truncated")?.try_into()?,
    ))
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn align(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

impl<'a> Pe<'a> {
    pub fn parse(data: &'a [u8]) -> anyhow::Result<Self> {
        ensure!(data.starts_with(b"MZ"), "not a PE image");
        let pe_offset = u32_at(data, 0x3c)? as usize;
        ensure!(
            data.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0"),
            "not a PE image"
        );
        let count = u16_at(data, pe_offset + 6)? as usize;
        let optional_size = u16_at(data, pe_offset + 20)? as usize;
        let optional = pe_offset + 24;
        ensure!(u16_at(data, optional)? == 0x20b, "not a PE32+ image");
        let table = optional + optional_size;
        let sections = (0..count)
            .map(|i| {
                let h = table + i * SECTION_HEADER;
                let raw = data.get(h..h + SECTION_HEADER).context("PE truncated")?;
                let name = String::from_utf8_lossy(&raw[..8])
                    .trim_end_matches('\0')
                    .to_string();
                Ok(Section {
                    name,
                    virtual_size: u32_at(raw, 8)?,
                    virtual_address: u32_at(raw, 12)?,
                    raw_size: u32_at(raw, 16)?,
                    raw_pointer: u32_at(raw, 20)?,
                    characteristics: u32_at(raw, 36)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for s in &sections {
            ensure!(
                (s.raw_pointer as usize + s.raw_size as usize) <= data.len(),
                "section {} past the image's end",
                s.name
            );
        }
        Ok(Self {
            data,
            pe_offset,
            optional,
            optional_size,
            sections,
        })
    }

    /// A section's contents, without the file alignment's padding.
    pub fn contents(&self, s: &Section) -> &'a [u8] {
        let start = s.raw_pointer as usize;
        &self.data[start..start + s.virtual_size.min(s.raw_size) as usize]
    }

    fn section_alignment(&self) -> anyhow::Result<u64> {
        Ok(u32_at(self.data, self.optional + 32)? as u64)
    }

    fn file_alignment(&self) -> anyhow::Result<u64> {
        Ok(u32_at(self.data, self.optional + 36)? as u64)
    }

    /// A new image of this one's first `keep` sections, then `appended`
    /// (name, contents) as read-only data, unsigned.
    pub fn rebuild(&self, keep: usize, appended: &[(&str, &[u8])]) -> anyhow::Result<Vec<u8>> {
        let salign = self.section_alignment()?;
        let falign = self.file_alignment()?;
        let kept = &self.sections[..keep];
        let last = kept.last().context("no sections to keep")?;
        let mut va = align(
            last.virtual_address as u64 + last.virtual_size as u64,
            salign,
        );
        let mut sections: Vec<(Section, &[u8])> = kept
            .iter()
            .map(|s| {
                let start = s.raw_pointer as usize;
                (s.clone(), &self.data[start..start + s.raw_size as usize])
            })
            .collect();
        for (name, contents) in appended {
            ensure!(name.len() <= 8, "section name {name} is too long");
            sections.push((
                Section {
                    name: name.to_string(),
                    virtual_size: u32::try_from(contents.len())?,
                    virtual_address: u32::try_from(va)?,
                    raw_size: u32::try_from(align(contents.len() as u64, falign))?,
                    raw_pointer: 0,
                    characteristics: CNT_INITIALIZED_DATA | MEM_READ,
                },
                contents,
            ));
            va = align(va + contents.len() as u64, salign);
        }

        let headers = align(
            (0x80 + 24 + self.optional_size + SECTION_HEADER * sections.len()) as u64,
            falign,
        );
        ensure!(
            headers <= self.sections[0].virtual_address as u64,
            "no room for the section table"
        );
        let mut out = Vec::with_capacity(
            headers as usize
                + sections
                    .iter()
                    .map(|s| s.0.raw_size as usize)
                    .sum::<usize>(),
        );
        // The DOS header alone, the PE header at 0x80.
        out.extend_from_slice(&self.data[..0x40]);
        put_u32(&mut out, 0x3c, 0x80);
        out.resize(0x80, 0);
        out.extend_from_slice(&self.data[self.pe_offset..self.optional + self.optional_size]);
        out[0x80 + 6..0x80 + 8].copy_from_slice(&u16::try_from(sections.len())?.to_le_bytes());
        let opt = 0x80 + 24;
        let (mut code, mut init) = (0u32, 0u32);
        for (s, _) in &sections {
            if s.characteristics & CNT_INITIALIZED_DATA != 0 {
                init += s.raw_size;
            } else {
                code += s.raw_size;
            }
        }
        put_u32(&mut out, opt + 4, code);
        put_u32(&mut out, opt + 8, init);
        put_u32(&mut out, opt + 56, u32::try_from(va)?);
        put_u32(&mut out, opt + 60, u32::try_from(headers)?);
        put_u32(&mut out, opt + 64, 0);
        out[opt + 144..opt + 152].fill(0);

        let mut pointer = headers as u32;
        for (s, _) in &mut sections {
            s.raw_pointer = pointer;
            pointer += s.raw_size;
        }
        for (s, _) in &sections {
            let mut h = [0u8; SECTION_HEADER];
            h[..s.name.len()].copy_from_slice(s.name.as_bytes());
            put_u32(&mut h, 8, s.virtual_size);
            put_u32(&mut h, 12, s.virtual_address);
            put_u32(&mut h, 16, s.raw_size);
            put_u32(&mut h, 20, s.raw_pointer);
            put_u32(&mut h, 36, s.characteristics);
            out.extend_from_slice(&h);
        }
        out.resize(headers as usize, 0);
        for (s, contents) in &sections {
            out.extend_from_slice(contents);
            out.resize(s.raw_pointer as usize + s.raw_size as usize, 0);
        }
        Ok(out)
    }

    /// The certificate table, if signed: its offset and size.
    fn certificates(&self) -> anyhow::Result<Option<(usize, usize)>> {
        let at = u32_at(self.data, self.optional + 144)? as usize;
        let size = u32_at(self.data, self.optional + 148)? as usize;
        Ok((at != 0).then_some((at, size)))
    }

    /// The Authenticode SHA-256 digest of an unsigned image.
    pub fn authenticode_digest(&self) -> anyhow::Result<[u8; 32]> {
        if self.certificates()?.is_some() {
            bail!("the image is signed");
        }
        let checksum = self.optional + 64;
        let security = self.optional + 144;
        let headers = u32_at(self.data, self.optional + 60)? as usize;
        let mut h = Sha256::new();
        h.update(&self.data[..checksum]);
        h.update(&self.data[checksum + 4..security]);
        h.update(&self.data[security + 8..headers]);
        let mut sections: Vec<&Section> = self.sections.iter().filter(|s| s.raw_size > 0).collect();
        sections.sort_by_key(|s| s.raw_pointer);
        let mut hashed = headers;
        for s in sections {
            let start = s.raw_pointer as usize;
            h.update(&self.data[start..start + s.raw_size as usize]);
            hashed += s.raw_size as usize;
        }
        if self.data.len() > hashed {
            h.update(&self.data[hashed..]);
        }
        Ok(h.finalize().into())
    }
}

/// The image with any signature taken off.
pub fn unsigned(mut out: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let pe = Pe::parse(&out)?;
    if let Some((at, _)) = pe.certificates()? {
        let optional = pe.optional;
        out.truncate(at);
        out[optional + 144..optional + 152].fill(0);
    }
    // The certificate table starts 8-byte aligned, and what precedes it is hashed.
    out.resize(align(out.len() as u64, 8) as usize, 0);
    Ok(out)
}

/// Appends a PKCS#7 Authenticode signature to an unsigned image.
pub fn attach(image: &mut Vec<u8>, pkcs7: &[u8]) -> anyhow::Result<()> {
    let optional = Pe::parse(image)?.optional;
    ensure!(
        image.len().is_multiple_of(8),
        "the image is not 8-byte aligned"
    );
    let len = 8 + align(pkcs7.len() as u64, 8) as usize;
    let at = image.len();
    image.extend_from_slice(&u32::try_from(len)?.to_le_bytes());
    image.extend_from_slice(&0x0200u16.to_le_bytes());
    image.extend_from_slice(&0x0002u16.to_le_bytes());
    image.extend_from_slice(pkcs7);
    image.resize(at + len, 0);
    put_u32(image, optional + 144, u32::try_from(at)?);
    put_u32(image, optional + 148, u32::try_from(len)?);
    Ok(())
}
