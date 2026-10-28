// SPDX-License-Identifier: Apache-2.0

//! MPEG TS/PS metadata, hand-rolled — a reduced port of the MPEG reader of
//! the `io` project by Dan Gohman, whose work is used here under Apache-2.0:
//! TS table sections (PAT programs, PMT stream map, SDT service names) and
//! PS pack/system headers (stream ids, mux rate). Elementary streams are
//! never decoded. See `NOTICE`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome};

pub struct MpegInfo;
impl Adapter for MpegInfo {
    fn name(&self) -> &'static str {
        "mpeg"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ts", "mpg", "mpeg", "m2ts", "vob", "mts"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(mpeg_text(data)?.into_bytes()))
    }
}

fn rd_u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn stream_type_name(st: u8) -> &'static str {
    match st {
        0x01 => "mpeg1-video",
        0x02 => "mpeg2-video",
        0x03 | 0x04 => "mp2",
        0x0F => "aac",
        0x10 => "mpeg4-video",
        0x11 => "aac-latm",
        0x1B => "avc",
        0x24 => "hevc",
        0x06 => "private",
        _ => "unknown",
    }
}

/// The transport packet size, 188 or 192, or `None` when neither probe lands.
///
/// M2TS carries the 188-byte TS packet behind a 4-byte timestamp prefix, so its
/// sync byte sits at offset 4 and never at 0 — which is why an extension whose
/// entire purpose is to NAME the 192-byte format was the one a 188-only probe
/// could not reach. Both sizes are confirmed by two sync bytes a whole packet
/// apart, so a single accidental 0x47 does not decide it: a 192-byte file
/// probed at 188 fails because data[0] is not 0x47, and vice versa.
fn ts_packet_size(data: &[u8]) -> Option<usize> {
    for (size, first) in [(188usize, 0usize), (192, 4)] {
        // Two whole packets, as the 188-only probe required: one sync byte is a
        // coincidence, two a whole packet apart is a container.
        if data.len() >= size * 2 && data[first] == 0x47 && data[first + size] == 0x47 {
            return Some(size);
        }
    }
    None
}

fn mpeg_text(data: &[u8]) -> Result<String> {
    if let Some(packet_size) = ts_packet_size(data) {
        ts_text(data, packet_size)
    } else if data.len() >= 4 && data[0..4] == [0x00, 0x00, 0x01, 0xBA] {
        ps_text(data)
    } else if data.len() < 188 {
        // A **decline**, not a failure: `.ts` is TypeScript as often as it is
        // a transport stream, and the registry resolves by extension alone.
        // Reporting "not an MPEG file" as an adapter failure put a note in
        // the corpus for every `.ts` source file — a line that was not in
        // the file, and a match the user could not explain. Stepping aside
        // silently is what a file that is not ours deserves.
        decline!("fewer bytes than one MPEG packet")
    } else {
        decline!("not an MPEG TS/PS file")
    }
}

// --------------------------------------------------------------------- TS

/// One elementary stream of a program: PID, stream-type name, ISO 639 language.
type Stream = (u16, String, Option<String>);
/// One program: number, SDT service name, PCR PID, its elementary streams.
type Program = (u16, Option<String>, Option<u16>, Vec<Stream>);

fn ts_text(data: &[u8], packet_size: usize) -> Result<String> {
    let kind = if packet_size == 192 {
        "m2ts"
    } else {
        "mpeg-ts"
    };
    let mut out = format!("container: {kind}\n");
    let mut programs: Vec<Program> = Vec::new();
    let mut pmt_pids: Vec<u16> = Vec::new();
    let mut pat_done = false;
    let mut sdt_done = false;
    let mut counts: Vec<(u16, u64)> = Vec::new();
    let mut total = 0u64;
    // Everything below indexes a packet from its own sync byte, so a chunk is
    // narrowed to the 188 bytes that carry the TS packet and the 4-byte M2TS
    // timestamp prefix is dropped. Taking the FIRST 188 bytes instead reads
    // from the prefix, where the sync byte never is.
    let skip = packet_size - 188;
    for chunk in data.chunks_exact(packet_size) {
        let packet = &chunk[skip..];
        if packet[0] != 0x47 {
            continue;
        }
        let pid = (((packet[1] as u16) & 0x1F) << 8) | packet[2] as u16;
        let adaptation = (packet[3] >> 4) & 0x03;
        *count(&mut counts, pid) += 1;
        total += 1;
        let payload_start = match adaptation {
            0 => continue,
            1 => 4,
            _ => 5 + *packet.get(4).unwrap_or(&184) as usize,
        };
        if packet[1] & 0x40 == 0 {
            continue;
        }
        match pid {
            0x0000 if !pat_done => {
                if let Some(section) = section_payload(packet, payload_start) {
                    if parse_pat(section, &mut pmt_pids, &mut programs) {
                        pat_done = true;
                    }
                }
            }
            0x0011 if !sdt_done => {
                if let Some(section) = section_payload(packet, payload_start) {
                    if parse_sdt(section, &mut programs) {
                        sdt_done = true;
                    }
                }
            }
            p if pmt_pids.contains(&p) => {
                if let Some(section) = section_payload(packet, payload_start) {
                    parse_pmt(section, &mut programs);
                    pmt_pids.retain(|&x| x != p);
                }
            }
            _ => {}
        }
    }
    if programs.is_empty() && counts.is_empty() {
        // Found nothing in it, not a failure: a transport stream with no
        // program map is a real thing, and the file's own bytes are still
        // worth searching.
        decline!("no TS packets decoded");
    }
    for (num, name, pcr, streams) in &programs {
        let label = name.clone().unwrap_or_else(|| format!("program {num}"));
        let _ = writeln!(out, "program: {label} (number {num})");
        if let Some(p) = pcr {
            let _ = writeln!(out, "pcr_pid: {p}");
        }
        for (spid, stype, lang) in streams {
            let mut line = format!("stream: {stype} pid {spid}");
            if let Some(l) = lang {
                let _ = write!(line, " [{l}]");
            }
            out.push_str(&line);
            out.push('\n');
        }
    }
    let _ = writeln!(out, "packets: {total}");
    for (pid, n) in counts.iter().take(16) {
        let _ = writeln!(out, "pid {pid}: {n} packets");
    }
    Ok(out)
}

fn count(counts: &mut Vec<(u16, u64)>, pid: u16) -> &mut u64 {
    let idx = match counts.iter().position(|(p, _)| *p == pid) {
        Some(i) => i,
        None => {
            counts.push((pid, 0));
            counts.len() - 1
        }
    };
    &mut counts[idx].1
}

fn section_payload(packet: &[u8], payload_start: usize) -> Option<&[u8]> {
    let pointer = *packet.get(payload_start)? as usize;
    let start = payload_start + 1 + pointer;
    if start + 3 > packet.len() {
        return None;
    }
    let section_length = (((packet[start + 1] as usize) & 0x0F) << 8) | packet[start + 2] as usize;
    let end = start + 3 + section_length;
    if end > packet.len() {
        return None;
    }
    Some(&packet[start..end])
}

fn parse_pat(section: &[u8], pmt_pids: &mut Vec<u16>, programs: &mut Vec<Program>) -> bool {
    if section.len() < 12 || section[0] != 0x00 {
        return false;
    }
    let section_length = (((section[1] as usize) & 0x0F) << 8) | section[2] as usize;
    let end = (3 + section_length).min(section.len());
    let mut p = 8usize;
    let mut any = false;
    while p + 4 <= end.saturating_sub(4) {
        let program_number = rd_u16be(section, p);
        let pid = (((section[p + 2] as u16) & 0x1F) << 8) | section[p + 3] as u16;
        if program_number != 0 {
            if !programs.iter().any(|pr| pr.0 == program_number) {
                programs.push((program_number, None, None, Vec::new()));
            }
            if !pmt_pids.contains(&pid) {
                pmt_pids.push(pid);
            }
            any = true;
        }
        p += 4;
    }
    any
}

fn parse_pmt(section: &[u8], programs: &mut [Program]) -> bool {
    if section.len() < 16 || section[0] != 0x02 {
        return false;
    }
    let program_number = rd_u16be(section, 3);
    let section_length = (((section[1] as usize) & 0x0F) << 8) | section[2] as usize;
    let end = (3 + section_length).min(section.len());
    let pcr_pid = (((section[8] as u16) & 0x1F) << 8) | section[9] as u16;
    let prog_info_len = (((section[10] as usize) & 0x0F) << 8) | section[11] as usize;
    let Some(program) = programs.iter_mut().find(|p| p.0 == program_number) else {
        return false;
    };
    program.2 = Some(pcr_pid);
    let mut p = 12 + prog_info_len;
    while p + 5 <= end.saturating_sub(4) {
        let st = section[p];
        let pid = (((section[p + 1] as u16) & 0x1F) << 8) | section[p + 2] as u16;
        let es_len = (((section[p + 3] as usize) & 0x0F) << 8) | section[p + 4] as usize;
        let mut language = None;
        let desc_end = (p + 5 + es_len).min(end);
        let mut d = p + 5;
        while d + 2 <= desc_end {
            let tag = section[d];
            let len = section[d + 1] as usize;
            if d + 2 + len > desc_end {
                break;
            }
            if tag == 0x0A && len >= 4 {
                language = Some(String::from_utf8_lossy(&section[d + 2..d + 6]).into_owned());
            }
            d += 2 + len;
        }
        program
            .3
            .push((pid, stream_type_name(st).to_string(), language));
        p = desc_end;
    }
    true
}

fn parse_sdt(section: &[u8], programs: &mut [Program]) -> bool {
    if section.len() < 15 || section[0] != 0x42 {
        return false;
    }
    let section_length = (((section[1] as usize) & 0x0F) << 8) | section[2] as usize;
    let end = (3 + section_length).min(section.len());
    // The service loop starts after the 3-byte section header
    // (table_id + section_syntax_indicator/reserved/section_length), the
    // 2-byte transport_stream_id, the 1-byte reserved/version/current_next,
    // the 2 section/last-section bytes, and then the 3-byte part of the first
    // entry the code consumes alongside its id: `service_id` (2) and
    // `reserved_future_use` (1) -- 3 + 2 + 1 + 2 + 3 = 11.
    //
    // Verified against the fixture rather than assumed: 11 is the only start
    // that yields the declared `descriptors_loop_length` of 24 and lands the
    // descriptor walk on the `0x48` service-descriptor tag. 7 and 8, the two
    // values the layout seems to invite, read the id correctly at 7 but then
    // compute a loop length of 3841 and start the walk at a `0x00` that is
    // not a descriptor at all.
    let mut p = 11usize;
    let mut any = false;
    while p + 5 <= end {
        let service_id = rd_u16be(section, p);
        let loop_len = (((section[p + 3] as usize) & 0x0F) << 8) | section[p + 4] as usize;
        let desc_end = (p + 5 + loop_len).min(end);
        let mut d = p + 5;
        while d + 2 <= desc_end {
            let tag = section[d];
            let len = section[d + 1] as usize;
            if d + 2 + len > desc_end {
                break;
            }
            if tag == 0x48 && len >= 3 {
                let prov_len = section[d + 3] as usize;
                let name_off = d + 4 + prov_len;
                if name_off < d + 2 + len {
                    let name_len = section[name_off] as usize;
                    let name_end = (name_off + 1 + name_len).min(d + 2 + len);
                    let name =
                        String::from_utf8_lossy(&section[name_off + 1..name_end]).into_owned();
                    if !name.is_empty() {
                        if let Some(prog) = programs.iter_mut().find(|pr| pr.0 == service_id) {
                            prog.1 = Some(name);
                        }
                        any = true;
                    }
                }
            }
            d += 2 + len;
        }
        p = desc_end;
    }
    any
}

// --------------------------------------------------------------------- PS

fn ps_text(data: &[u8]) -> Result<String> {
    let mut out = String::from("container: mpeg-ps\n");
    let mut stream_ids: Vec<(u16, u64)> = Vec::new();
    let mut mux_rate: Option<u64> = None;
    let mut first_scr_ns: Option<f64> = None;
    let mut last_scr_ns: Option<f64> = None;
    let mut total = 0u64;
    let mut pos = 0usize;
    let mut guard = 0u64;
    while pos + 6 <= data.len() {
        guard += 1;
        if guard > 2_000_000 {
            break;
        }
        if data[pos] != 0 || data[pos + 1] != 0 || data[pos + 2] != 1 {
            pos += 1;
            continue;
        }
        let code = data[pos + 3];
        match code {
            0xBA => {
                let b = &data[pos..];
                if b.len() >= 14 && (b[4] >> 6) & 0x03 == 0x01 {
                    let base = (((b[4] as u64 & 0x38) >> 3) << 30)
                        | ((b[4] as u64 & 0x03) << 28)
                        | ((b[5] as u64) << 20)
                        | (((b[6] as u64 & 0xF8) >> 3) << 15)
                        | ((b[6] as u64 & 0x03) << 13)
                        | ((b[7] as u64) << 5)
                        | ((b[8] as u64 & 0xF8) >> 3);
                    let scr_ns = base as f64 / 90_000.0 * 1_000_000.0;
                    if first_scr_ns.is_none() {
                        first_scr_ns = Some(scr_ns);
                    }
                    last_scr_ns = Some(scr_ns);
                    pos += 14;
                } else {
                    pos += 12;
                }
            }
            0xBB => {
                let b = &data[pos..];
                if b.len() >= 12 {
                    let len = rd_u16be(b, 4) as usize;
                    if b.len() >= 6 + len {
                        let rate_bound = (((b[6] as u64) & 0x7F) << 15)
                            | ((b[7] as u64) << 7)
                            | ((b[8] as u64) >> 1);
                        mux_rate = Some(rate_bound * 50);
                        let mut p = 12usize;
                        let end = 6 + len;
                        while p + 3 <= end {
                            let id = b[p] as u16;
                            if !(0xBC..=0xFF).contains(&id) {
                                break;
                            }
                            *count(&mut stream_ids, id) += 1;
                            p += 3;
                        }
                    }
                }
                pos += 6;
            }
            0xBC | 0xBE | 0xBF => {
                if pos + 6 > data.len() {
                    break;
                }
                let len = rd_u16be(data, pos + 4) as usize;
                pos += 6 + len;
            }
            id if (0xC0..=0xEF).contains(&id) || id == 0xBD || id == 0xFA => {
                if pos + 6 > data.len() {
                    break;
                }
                *count(&mut stream_ids, id as u16) += 1;
                total += 1;
                let len = rd_u16be(data, pos + 4) as usize;
                pos += if len == 0 { 6 } else { 6 + len };
            }
            _ => pos += 4,
        }
    }
    if stream_ids.is_empty() && mux_rate.is_none() {
        decline!("no MPEG-PS structure decoded");
    }
    if let Some(rate) = mux_rate {
        let _ = writeln!(out, "mux_rate: {rate}");
    }
    for (id, n) in &stream_ids {
        let kind = match *id {
            0xE0..=0xEF => "video",
            0xC0..=0xDF => "audio",
            0xBD => "private-stream-1",
            0xFD => "ancillary",
            _ => "stream",
        };
        let _ = writeln!(out, "stream: {kind} id 0x{id:02X} ({n} packets)");
    }
    if let (Some(rate), Some(first), Some(last)) = (mux_rate, first_scr_ns, last_scr_ns) {
        if last > first && rate > 0 {
            let _ = writeln!(out, "duration_s: {:.1}", (last - first) * 8.0 / rate as f64);
        }
    }
    let _ = writeln!(out, "pes_packets: {total}");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts_packet(pid: u16, pusi: bool, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0x47,
            ((pusi as u8) << 6) | ((pid >> 8) as u8 & 0x1F),
            pid as u8,
            0x10,
        ];
        v.extend_from_slice(payload);
        v.resize(188, 0xFF);
        v
    }

    fn section(table_id: u8, body_after_len: &[u8]) -> Vec<u8> {
        let total = body_after_len.len() + 4;
        let mut v = vec![table_id, 0xB0 | ((total >> 8) as u8 & 0x0F), total as u8];
        v.extend_from_slice(body_after_len);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    fn pat_section(program: u16, pmt_pid: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0xC1, 0, 0]);
        body.extend_from_slice(&program.to_be_bytes());
        body.push(0xE0 | ((pmt_pid >> 8) as u8 & 0x1F));
        body.push(pmt_pid as u8);
        section(0x00, &body)
    }

    fn pmt_section(program: u16, pcr_pid: u16, streams: &[(u8, u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&program.to_be_bytes());
        body.extend_from_slice(&[0xC1, 0, 0]);
        body.push(0xE0 | ((pcr_pid >> 8) as u8 & 0x1F));
        body.push(pcr_pid as u8);
        body.extend_from_slice(&[0xF0, 0x00]);
        for (st, pid) in streams {
            body.push(*st);
            body.push(0xE0 | ((pid >> 8) as u8 & 0x1F));
            body.push(*pid as u8);
            body.extend_from_slice(&[0xF0, 0x00]);
        }
        section(0x02, &body)
    }

    fn sdt_section(program: u16, service_name: &str) -> Vec<u8> {
        let mut descriptor = vec![0x48u8];
        let prov = b"upstream";
        descriptor.push((1 + 1 + prov.len() + 1 + service_name.len()) as u8);
        descriptor.push(0x01);
        descriptor.push(prov.len() as u8);
        descriptor.extend_from_slice(prov);
        descriptor.push(service_name.len() as u8);
        descriptor.extend_from_slice(service_name.as_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[0xC1, 0, 0]);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(0xFF);
        body.extend_from_slice(&program.to_be_bytes());
        body.push(0xFC);
        body.push(0xF0 | ((descriptor.len() >> 8) as u8 & 0x0F));
        body.push(descriptor.len() as u8);
        body.extend_from_slice(&descriptor);
        section(0x42, &body)
    }

    fn with_pointer(s: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(s);
        v
    }

    fn mini_ts() -> Vec<u8> {
        let mut v = ts_packet(0x0000, true, &with_pointer(&pat_section(1, 0x1000)));
        v.extend_from_slice(&ts_packet(
            0x1000,
            true,
            &with_pointer(&pmt_section(1, 0x0101, &[(0x1B, 0x0101), (0x0F, 0x0102)])),
        ));
        v.extend_from_slice(&ts_packet(
            0x0011,
            true,
            &with_pointer(&sdt_section(1, "Zircaloy TV")),
        ));
        v.extend_from_slice(&ts_packet(0x0101, false, &[0x00, 0x00, 0x01, 0xE0]));
        v
    }

    fn mini_ps() -> Vec<u8> {
        let mut v = vec![
            0x00, 0x00, 0x01, 0xBA, 0x44, 0x00, 0x04, 0x00, 0x04, 0x01, 0x89, 0xC3, 0xF8, 0x00,
        ];
        let mut sys = vec![0x00, 0x00, 0x01, 0xBB];
        let mut body = vec![0x80, 0x0C, 0xA0, 0xE1, 0xE2, 0xFF];
        body.extend_from_slice(&[0xE0, 0xE0, 0xE8, 0xC0, 0xC0, 0xC8]);
        sys.extend_from_slice(&(body.len() as u16).to_be_bytes());
        sys.extend_from_slice(&body);
        v.extend_from_slice(&sys);
        v.extend_from_slice(&[
            0x00, 0x00, 0x01, 0xE0, 0x00, 0x08, 0x80, 0x00, 0x00, 0, 0, 0, 0, 0,
        ]);
        v
    }

    #[test]
    fn ts_metadata_text() {
        let text = mpeg_text(&mini_ts()).unwrap();
        assert!(text.contains("container: mpeg-ts"), "{text}");
        assert!(text.contains("program: Zircaloy TV (number 1)"), "{text}");
        assert!(text.contains("stream: avc pid 257"), "{text}");
        assert!(text.contains("stream: aac pid 258"), "{text}");
        assert!(text.contains("packets: 4"), "{text}");
    }

    /// Re-wrap a 188-byte TS stream as M2TS: 4 bytes of 33-bit timestamp prefix
    /// in front of every packet, so the sync byte moves from offset 0 to offset
    /// 4. The stream is the same stream, so the metadata must be the same
    /// metadata -- which is the whole claim being tested. A real `.m2ts` from
    /// ffmpeg is what caught the original 188-only probe; this is the case that
    /// would have caught it again.
    fn to_m2ts(ts: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ts.len() / 188 * 192);
        for (i, packet) in ts.as_chunks::<188>().0.iter().enumerate() {
            out.extend_from_slice(&(i as u32).to_le_bytes());
            out.extend_from_slice(packet);
        }
        out
    }

    #[test]
    fn m2ts_is_read_with_a_four_byte_prefix_per_packet() {
        let ts = mini_ts();
        let m2 = to_m2ts(&ts);
        assert_eq!(m2.len(), ts.len() / 188 * 192);
        assert_eq!(m2[0], 0, "the prefix, not the sync byte, leads the file");
        assert_eq!(m2[4], 0x47, "the sync byte moved to offset 4");
        let text = mpeg_text(&m2).unwrap();
        assert!(text.contains("container: m2ts"), "{text}");
        assert!(text.contains("program: Zircaloy TV (number 1)"), "{text}");
        assert!(text.contains("stream: avc pid 257"), "{text}");
        assert!(text.contains("packets: 4"), "{text}");
    }

    /// The probe must not answer 192 for a plain 188-byte stream: a single
    /// accidental 0x47 at offset 4 must not decide the packet size.
    #[test]
    fn a_sync_byte_at_offset_four_does_not_make_a_ts_stream_look_like_m2ts() {
        let mut ts = mini_ts();
        ts[4] = 0x47;
        let text = mpeg_text(&ts).unwrap();
        assert!(text.contains("container: mpeg-ts"), "{text}");
    }

    #[test]
    fn ps_metadata_text() {
        let text = mpeg_text(&mini_ps()).unwrap();
        assert!(text.contains("container: mpeg-ps"), "{text}");
        assert!(text.contains("mux_rate:"), "{text}");
        assert!(text.contains("stream: video id 0xE0"), "{text}");
        assert!(text.contains("stream: audio id 0xC0"), "{text}");
    }

    #[test]
    fn rejects_non_mpeg() {
        assert!(mpeg_text(b"").is_err());
        assert!(mpeg_text(&vec![b'x'; 400]).is_err());
    }

    mod fuzz {
        use super::*;

        #[test]
        fn mpeg_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("ts", mini_ts()),
                    ("ps", mini_ps()),
                    ("sync-only", vec![0x47, 0x00, 0x00, 0x10]),
                    ("empty", vec![]),
                ],
                1500,
                "mpeg",
                |data| {
                    let _ = MpegInfo.extract(data, "fuzz.ts");
                },
            );
        }
    }
}
