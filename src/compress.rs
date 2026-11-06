//! Inline compression: one zstd stream per data connection, flushed after every frame so each
//! frame can be decoded on arrival while the compression context (history) carries across files.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use zstd::stream::raw::{Decoder, Encoder, InBuffer, Operation, OutBuffer};

/// Formats that are already compressed; sending them raw saves CPU and gains nothing.
const INCOMPRESSIBLE: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "br", "cab", "jpg", "jpeg", "png", "gif",
    "webp", "heic", "avif", "mp3", "mp4", "m4a", "m4v", "mkv", "avi", "mov", "webm", "ogg", "opus", "flac",
    "aac", "pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "msi", "iso", "dmg", "woff2",
];

/// After this many samples of an extension, stop compressing it if it doesn't shrink.
const LEARN_SAMPLES: u32 = 16;
const USELESS_RATIO: f64 = 0.97;

pub fn ext_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn known_incompressible(ext: &str) -> bool {
    INCOMPRESSIBLE.contains(&ext)
}

/// Decides per file type whether to compress, learning from what earlier frames achieved.
pub struct Policy {
    pub level: i32,
    seen: Mutex<HashMap<String, (u64, u64, u32)>>,
}

impl Policy {
    pub fn new(level: i32) -> Self {
        Policy { level, seen: Mutex::new(HashMap::new()) }
    }

    pub fn should_compress(&self, ext: &str) -> bool {
        if self.level == 0 || known_incompressible(ext) {
            return false;
        }
        match self.seen.lock().unwrap().get(ext) {
            Some(&(raw, wire, n)) if n >= LEARN_SAMPLES => (wire as f64) < (raw as f64) * USELESS_RATIO,
            _ => true,
        }
    }

    pub fn record(&self, ext: &str, raw: u64, wire: u64) {
        let mut seen = self.seen.lock().unwrap();
        let e = seen.entry(ext.to_string()).or_insert((0, 0, 0));
        e.0 += raw;
        e.1 += wire;
        e.2 += 1;
    }

    /// Per-extension (raw, wire) totals, largest first.
    pub fn summary(&self) -> Vec<(String, u64, u64)> {
        let mut v: Vec<_> = self.seen.lock().unwrap().iter().map(|(k, &(r, w, _))| (k.clone(), r, w)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

pub struct FrameEncoder(Encoder<'static>);

impl FrameEncoder {
    pub fn new(level: i32, dict: &[u8]) -> Result<Self> {
        let enc = if dict.is_empty() { Encoder::new(level)? } else { Encoder::with_dictionary(level, dict)? };
        Ok(FrameEncoder(enc))
    }

    /// Changes the compression level mid-stream (zstd applies it from the next block on); the history and
    /// therefore the receiver's decoder are unaffected.
    pub fn set_level(&mut self, level: i32) -> Result<()> {
        self.0.set_parameter(zstd::stream::raw::CParameter::CompressionLevel(level))?;
        Ok(())
    }

    /// Compresses `input` into `out` (replacing its contents) and flushes, so the receiver can
    /// decode this frame completely without waiting for more data.
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        out.reserve(zstd::zstd_safe::compress_bound(input.len()) + 1024);
        let cap = out.capacity();
        let mut ob = OutBuffer::around(out);
        let mut ib = InBuffer::around(input);
        while ib.pos() < input.len() {
            let before = (ib.pos(), ob.pos());
            self.0.run(&mut ib, &mut ob)?;
            if (ib.pos(), ob.pos()) == before && ob.pos() == cap {
                bail!("compression buffer too small");
            }
        }
        loop {
            let remaining = self.0.flush(&mut ob)?;
            if remaining == 0 {
                break;
            }
            if ob.pos() == cap {
                bail!("compression buffer too small");
            }
        }
        Ok(())
    }
}

pub struct FrameDecoder(Decoder<'static>);

impl FrameDecoder {
    pub fn new(dict: &[u8]) -> Result<Self> {
        let dec = if dict.is_empty() { Decoder::new()? } else { Decoder::with_dictionary(dict)? };
        Ok(FrameDecoder(dec))
    }

    pub fn decompress(&mut self, wire: &[u8], raw_len: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(raw_len);
        {
            let mut ob = OutBuffer::around(&mut out);
            let mut ib = InBuffer::around(wire);
            let mut stalls = 0;
            while ib.pos() < wire.len() || ob.pos() < raw_len {
                let before = (ib.pos(), ob.pos());
                self.0.run(&mut ib, &mut ob).context("corrupt compressed frame")?;
                if (ib.pos(), ob.pos()) == before {
                    stalls += 1;
                    if stalls > 2 {
                        bail!("corrupt compressed frame (no progress)");
                    }
                }
            }
        }
        if out.len() != raw_len {
            bail!("corrupt compressed frame (length {} != {raw_len})", out.len());
        }
        Ok(out)
    }
}

/// Trains a shared dictionary from file samples; None if training fails or isn't worthwhile.
pub fn train_dict(samples: &[Vec<u8>]) -> Option<Vec<u8>> {
    if samples.len() < 100 {
        return None;
    }
    zstd::dict::from_samples(samples, 110 * 1024).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_share_context_and_roundtrip() {
        let files: Vec<Vec<u8>> = (0..50)
            .map(|i| format!("<doc id=\"{i}\"><title>Device for copying files {i}</title><body>...</body></doc>").into_bytes())
            .collect();
        let mut enc = FrameEncoder::new(3, &[]).unwrap();
        let mut dec = FrameDecoder::new(&[]).unwrap();
        let mut wire = Vec::new();
        let (mut raw_total, mut wire_total) = (0, 0);
        for f in &files {
            enc.compress(f, &mut wire).unwrap();
            raw_total += f.len();
            wire_total += wire.len();
            assert_eq!(&dec.decompress(&wire, f.len()).unwrap(), f);
        }
        // Later frames reuse earlier history, so the stream as a whole compresses well.
        assert!(wire_total * 3 < raw_total, "{wire_total} vs {raw_total}");
    }

    #[test]
    fn level_change_mid_stream_roundtrips() {
        let mut enc = FrameEncoder::new(1, &[]).unwrap();
        let mut dec = FrameDecoder::new(&[]).unwrap();
        let mut wire = Vec::new();
        for (i, level) in [1, 3, 7, 9, 3, 1].iter().enumerate() {
            enc.set_level(*level).unwrap();
            let data = format!("<doc n=\"{i}\">{}</doc>", "document claim text ".repeat(200)).into_bytes();
            enc.compress(&data, &mut wire).unwrap();
            assert_eq!(dec.decompress(&wire, data.len()).unwrap(), data);
        }
        // The new level really applies: switching 1 -> 19 compresses like a fresh level-19 encoder.
        let data = format!("{}", "claim text with variation ".repeat(20000)).into_bytes();
        let noisy: Vec<u8> = (0..400_000u32).map(|i| ((i * 7919) % 251) as u8 ^ (i / 1000) as u8).chain(data).collect();
        let (mut a, mut b) = (FrameEncoder::new(1, &[]).unwrap(), FrameEncoder::new(1, &[]).unwrap());
        b.set_level(19).unwrap();
        let (mut wa, mut wb) = (Vec::new(), Vec::new());
        a.compress(&noisy, &mut wa).unwrap();
        b.compress(&noisy, &mut wb).unwrap();
        assert!(wb.len() * 2 < wa.len(), "{} vs {}", wb.len(), wa.len());
    }

    #[test]
    fn dictionary_roundtrip() {
        let samples: Vec<Vec<u8>> = (0..300)
            .map(|i| format!("{{\"doc\":{i},\"office\":\"EP\",\"kind\":\"A1\",\"lang\":\"de\",\"pages\":{}}}", i % 17).into_bytes())
            .collect();
        let dict = train_dict(&samples).expect("dictionary");
        let mut enc = FrameEncoder::new(3, &dict).unwrap();
        let mut dec = FrameDecoder::new(&dict).unwrap();
        let mut wire = Vec::new();
        enc.compress(&samples[7], &mut wire).unwrap();
        assert_eq!(dec.decompress(&wire, samples[7].len()).unwrap(), samples[7]);
    }

    #[test]
    fn empty_and_incompressible_frames() {
        let mut enc = FrameEncoder::new(1, &[]).unwrap();
        let mut dec = FrameDecoder::new(&[]).unwrap();
        let mut wire = Vec::new();
        enc.compress(&[], &mut wire).unwrap();
        assert!(dec.decompress(&wire, 0).unwrap().is_empty());
        let mut noise = vec![0u8; 300_000];
        getrandom::getrandom(&mut noise).unwrap();
        enc.compress(&noise, &mut wire).unwrap();
        assert_eq!(dec.decompress(&wire, noise.len()).unwrap(), noise);
    }

    #[test]
    fn policy_learns() {
        let p = Policy::new(3);
        assert!(!p.should_compress("zip"));
        assert!(p.should_compress("bin"));
        for _ in 0..LEARN_SAMPLES {
            p.record("bin", 1000, 999);
        }
        assert!(!p.should_compress("bin"));
        assert_eq!(ext_of("a/b.tar.GZ"), "gz");
        assert_eq!(ext_of("a/.hidden"), "");
    }
}

