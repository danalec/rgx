// SPDX-License-Identifier: Apache-2.0

//! The **PLT** (HP-GL plotter) rendering.
//!
//! **What a PLT is.** A drawing as a stream of *plotter commands*: a
//! two-letter mnemonic, its parameters, and a semicolon. `PU` lifts the
//! pen, `PD` lowers it, `PA` gives a point in the plotter's own units, `SP`
//! picks a pen, `CI` draws a circle, `LB` writes a label. The commands are
//! the drawing: the picture is not written down anywhere, it is the path the
//! pen took.
//!
//! **Why it is rendered and not revealed.** The bytes are text, and `rg`
//! reads them: every mnemonic and every number is already greppable. An
//! adapter that *answered* for the file would replace bytes ripgrep already
//! searches, and rgx would answer a subset of what `rg` answers — the one
//! thing this crate is built not to do. So this is [`Reach::Render`], the
//! same reach the DXF of this crate declares: under the default policy the
//! file's own bytes are the answer, and the rendering is what the user asks
//! for explicitly.
//!
//! **What the rendering is for.** The drawing is not in the file. A polyline
//! is a `PD` here and a `PA` there, with the points split across commands
//! and the pen state carrying the rest of the meaning. "A polyline through
//! (0,11181) and (230,11507)" is one phrase in the rendering and two
//! numbers in the file. That is the whole of it.
//!
//! **What it does not do.** It does not project the coordinates. `SC` and
//! `IP` decide what a number means, and they are reported rather than
//! applied. The arcs are reported as the arcs the file names, not as the
//! points they pass through. The commands of HP-GL/2 that carry binary
//! data are not decoded: a file whose stream is not a run of mnemonics is
//! declined rather than half-read.
//!
//! **The fixture.** `testdata/sample.plt` is a capture from an HP 8595E
//! plotter, taken from the HPGL-Plotter project
//! (<https://github.com/VK2BEA/HPGL-Plotter>), Apache-2.0, Copyright 2022
//! Michael G. Katzmann. It is used here unmodified.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{decline, Adapter, NoStdFloat, Outcome, Reach, Result};

/// Bytes one rendering may produce.
///
/// The input is already in memory — the walker reads the file whole before
/// an adapter sees it — so this is not a bound on what can be read, it is a
/// bound on how much *more* the rendering may cost.
const MAX_RENDER: usize = 64 << 20;

/// The character that ends a label when the file does not say otherwise.
///
/// HP-GL's default label terminator is ETX.
const DEFAULT_TERMINATOR: u8 = 0x03;

/// A drawing, as a rendering.
pub struct Plt;

impl Adapter for Plt {
    fn name(&self) -> &'static str {
        "plt"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["plt", "hpgl", "hgl"]
    }

    /// The file is text `rg` already reads: a rendering, never an answer.
    fn reach(&self) -> Reach {
        Reach::Render
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render_plt(data)?.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The plotter
// ---------------------------------------------------------------------------

/// Where the pen is, what it draws with, and what it has drawn so far.
struct Plotter {
    /// The pen is down: the coordinates draw.
    down: bool,
    /// The coordinates are relative to the current position.
    relative: bool,
    /// Where the pen is.
    x: f64,
    y: f64,
    /// The selected pen.
    pen: u32,
    /// The character that ends a label.
    terminator: u8,
    /// The points of the stroke being drawn.
    stroke: Vec<(f64, f64)>,
    /// The pen that started the stroke being drawn.
    stroke_pen: u32,
}

impl Plotter {
    fn new() -> Self {
        Self {
            down: false,
            relative: false,
            x: 0.0,
            y: 0.0,
            pen: 0,
            terminator: DEFAULT_TERMINATOR,
            stroke: Vec::new(),
            stroke_pen: 0,
        }
    }

    /// The point a coordinate pair names, in the pen's own units.
    ///
    /// In relative mode a coordinate is an offset from where the pen is;
    /// in absolute mode it is where the pen goes.
    fn resolve(&self, x: f64, y: f64) -> (f64, f64) {
        if self.relative {
            (self.x + x, self.y + y)
        } else {
            (x, y)
        }
    }

    /// Move the pen, drawing if it is down.
    fn travel(&mut self, x: f64, y: f64) {
        let (nx, ny) = self.resolve(x, y);
        if self.down {
            if self.stroke.is_empty() {
                self.stroke.push((self.x, self.y));
                self.stroke_pen = self.pen;
            }
            self.stroke.push((nx, ny));
        }
        self.x = nx;
        self.y = ny;
    }

    /// Write the stroke being drawn, if it drew anything.
    fn flush(&mut self, out: &mut String) {
        if self.stroke.len() > 1 {
            let points = points(&self.stroke);
            let _ = writeln!(out, "pen {}: polyline {points}", self.stroke_pen);
        }
        self.stroke.clear();
    }
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// A drawing, as text.
fn render_plt(data: &[u8]) -> Result<String> {
    let mut out = String::new();
    let mut plotter = Plotter::new();
    let mut i = 0usize;
    let mut known = 0usize;

    // HP-GL/2 files open with an escape sequence that introduces the
    // language. It is not a command and it is not a drawing.
    if data.starts_with(b"\x1b%-1B") {
        i = 5;
    }

    while i < data.len() {
        // Whitespace between the commands is not part of one.
        while i < data.len() && data[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= data.len() {
            break;
        }

        // A command may be empty: a file writes `LT;;` to end a line type
        // with no parameter and then an empty command.
        if data[i] == b';' {
            i += 1;
            continue;
        }

        // A command is two letters. A file that does not have them here is
        // not HP-GL, and saying so is better than reading half of it.
        if i + 1 >= data.len()
            || !data[i].is_ascii_alphabetic()
            || !data[i + 1].is_ascii_alphabetic()
        {
            decline!("byte {i} is not an hp-gl mnemonic");
        }
        let name = &data[i..i + 2];
        i += 2;

        // The parameters run to the semicolon that ends the command.
        let start = i;
        while i < data.len() && data[i] != b';' {
            i += 1;
        }
        let params = &data[start..i];
        if i < data.len() {
            i += 1;
        }

        if plotter.run(name, params, &mut out) {
            known += 1;
        }
        if out.len() > MAX_RENDER {
            let _ = writeln!(
                out,
                "[the rendering stops here: the drawing is larger than {MAX_RENDER} bytes]"
            );
            break;
        }
    }

    plotter.flush(&mut out);
    if known == 0 {
        decline!("no hp-gl command in the file");
    }
    Ok(out)
}

impl Plotter {
    /// Run one command. Returns whether it was one this reader knows.
    fn run(&mut self, name: &[u8], params: &[u8], out: &mut String) -> bool {
        match name {
            b"IN" => {
                // Initialize: the plotter forgets everything.
                *self = Plotter::new();
                true
            }
            b"SP" => {
                if let Some(pen) = first_number(params) {
                    self.pen = if pen < 0.0 { 0 } else { pen as u32 };
                }
                true
            }
            b"PU" => {
                self.flush(out);
                self.down = false;
                self.walk(params);
                true
            }
            b"PD" => {
                self.down = true;
                self.walk(params);
                true
            }
            b"PA" => {
                self.relative = false;
                self.walk(params);
                true
            }
            b"PR" => {
                self.relative = true;
                self.walk(params);
                true
            }
            b"AT" => {
                // The absolute pen position: a move, never a line.
                let (x, y) = pair(params);
                self.x = x;
                self.y = y;
                true
            }
            b"CI" => {
                let radius = first_number(params).unwrap_or(0.0);
                let (x, y) = (self.x, self.y);
                let _ = writeln!(
                    out,
                    "pen {}: circle centre ({},{x}) radius {}",
                    self.pen, y, radius
                );
                true
            }
            b"AA" | b"AR" => {
                // An arc: the pen turns about the point it is at now, and
                // stops at the point it is given.
                let numbers = numbers(params);
                if numbers.len() < 3 {
                    return true;
                }
                let relative = name == b"AR";
                let (x, y) = if relative {
                    (self.x + numbers[0], self.y + numbers[1])
                } else {
                    (numbers[0], numbers[1])
                };
                let sweep = numbers[2];
                let (cx, cy) = (self.x, self.y);
                let _ = writeln!(
                    out,
                    "pen {}: arc centre ({cx},{cy}) to ({x},{y}) sweep {sweep}",
                    self.pen
                );
                self.x = x;
                self.y = y;
                true
            }
            b"EA" | b"ER" | b"RA" | b"RR" => {
                // A rectangle: the current position is one corner and the
                // parameter the other.
                let (x, y) = pair(params);
                let (x, y) = self.resolve(x, y);
                let (x0, y0) = (self.x, self.y);
                let kind = if name == b"EA" || name == b"ER" {
                    "rectangle"
                } else {
                    "filled rectangle"
                };
                let _ = writeln!(out, "pen {}: {kind} ({x0},{y0}) to ({x},{y})", self.pen);
                self.x = x;
                self.y = y;
                true
            }
            b"EW" => {
                let numbers = numbers(params);
                if numbers.len() < 3 {
                    return true;
                }
                let (cx, cy) = (self.x, self.y);
                let _ = writeln!(
                    out,
                    "pen {}: wedge centre ({cx},{cy}) radius {} start {} sweep {}",
                    self.pen, numbers[0], numbers[1], numbers[2]
                );
                true
            }
            b"LB" => {
                let text = self.label(params);
                let (x, y) = (self.x, self.y);
                let _ = writeln!(out, "pen {}: label {text:?} at ({x},{y})", self.pen);
                true
            }
            b"DT" => {
                // The label terminator: the first character of the
                // parameters is the new one.
                if let Some(byte) = params.first() {
                    self.terminator = *byte;
                }
                true
            }
            b"SC" => {
                let numbers = numbers(params);
                if numbers.is_empty() {
                    return true;
                }
                let mut line = String::new();
                for n in &numbers {
                    let _ = write!(line, " {}", coord(*n));
                }
                let _ = writeln!(out, "scale:{line}");
                true
            }
            b"IP" | b"DP" => {
                let numbers = numbers(params);
                if numbers.len() < 4 {
                    return true;
                }
                let kind = if name == b"IP" {
                    "window"
                } else {
                    "default window"
                };
                let _ = writeln!(
                    out,
                    "{kind}: ({},{}) ({},{})",
                    coord(numbers[0]),
                    coord(numbers[1]),
                    coord(numbers[2]),
                    coord(numbers[3])
                );
                true
            }
            b"SI" | b"SR" => {
                let numbers = numbers(params);
                if numbers.len() < 2 {
                    return true;
                }
                let kind = if name == b"SI" {
                    "character size"
                } else {
                    "relative character size"
                };
                let _ = writeln!(out, "{kind}: ({},{})", coord(numbers[0]), coord(numbers[1]));
                true
            }
            b"WU" => {
                if let Some(units) = first_number(params) {
                    let _ = writeln!(out, "user units: {}", coord(units));
                }
                true
            }
            b"DI" => {
                let numbers = numbers(params);
                if numbers.len() < 2 {
                    return true;
                }
                let _ = writeln!(
                    out,
                    "direction: ({},{})",
                    coord(numbers[0]),
                    coord(numbers[1])
                );
                true
            }
            _ => false,
        }
    }

    /// Move the pen through the coordinate pairs of a command.
    fn walk(&mut self, params: &[u8]) {
        let numbers = numbers(params);
        let mut i = 0usize;
        while i + 1 < numbers.len() {
            self.travel(numbers[i], numbers[i + 1]);
            i += 2;
        }
    }

    /// The text of a label: the parameters up to the label terminator.
    fn label(&self, params: &[u8]) -> String {
        let end = params
            .iter()
            .position(|b| *b == self.terminator)
            .unwrap_or(params.len());
        String::from_utf8_lossy(&params[..end]).into_owned()
    }
}

// ---------------------------------------------------------------------------
// Numbers and points
// ---------------------------------------------------------------------------

/// The numbers of a command's parameters.
///
/// A parameter that is not a number is not a number: it is skipped, and
/// the command that wanted it says so by drawing less than it asked for.
fn numbers(params: &[u8]) -> Vec<f64> {
    let text = String::from_utf8_lossy(params);
    let mut out = Vec::new();
    for part in text.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        if let Some(value) = number(token) {
            out.push(value);
        }
    }
    out
}

/// The first number of a command's parameters.
fn first_number(params: &[u8]) -> Option<f64> {
    numbers(params).first().copied()
}

/// A coordinate pair: the first two numbers, or the origin.
fn pair(params: &[u8]) -> (f64, f64) {
    let numbers = numbers(params);
    match (numbers.first(), numbers.get(1)) {
        (Some(x), Some(y)) => (*x, *y),
        (Some(x), None) => (*x, 0.0),
        _ => (0.0, 0.0),
    }
}

/// A number as a drawing writes it.
///
/// The parser this crate carries is the JSON one, and JSON writes neither
/// `0.` nor `.5`; HP-GL writes both.
fn number(token: &str) -> Option<f64> {
    let mut normalised = String::with_capacity(token.len() + 2);
    if let Some(rest) = token.strip_prefix('.') {
        normalised.push('0');
        normalised.push_str(rest);
    } else if let Some(rest) = token.strip_suffix('.') {
        normalised.push_str(rest);
        normalised.push_str(".0");
    } else {
        normalised.push_str(token);
    }
    f64::parse(&normalised).ok()
}

/// A number as the rendering writes it: an integer without a decimal
/// point, anything else with one.
fn coord(value: f64) -> String {
    let mut out = String::new();
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        let _ = write!(out, "{}", value as i64);
    } else {
        let _ = write!(out, "{value}");
    }
    out
}

/// The points of a stroke: `(x,y) (x,y)`.
fn points(stroke: &[(f64, f64)]) -> String {
    let mut out = String::new();
    for (index, (x, y)) in stroke.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "({},{})", coord(*x), coord(*y));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The fixture: a capture from an HP 8595E plotter.
    const FIXTURE: &[u8] = include_bytes!("../testdata/sample.plt");

    fn render(data: &[u8]) -> String {
        render_plt(data).expect("the fixture renders")
    }

    #[test]
    fn a_polyline_is_one_line_with_its_points() {
        let out = render(FIXTURE);
        assert!(
            out.contains("pen 1: polyline (0,11181) (230,11507)"),
            "the rendering should carry the first polyline, got:\n{out}"
        );
    }

    #[test]
    fn a_label_is_its_text_and_where_it_sits() {
        let out = render(FIXTURE);
        assert!(
            out.contains("label \"#RES BW 3.\""),
            "the rendering should carry the label text, got:\n{out}"
        );
    }

    #[test]
    fn a_file_that_is_not_hp_gl_is_declined() {
        // A gnuplot script is not a plotter file, and the extension is
        // shared: the reader has to say no.
        let err = render_plt(b"set terminal png\nplot sin(x)\n").unwrap_err();
        assert!(err.to_string().contains("hp-gl"), "{err}");
    }

    #[test]
    fn a_file_with_no_command_is_declined() {
        let err = render_plt(b"hello world\n").unwrap_err();
        assert!(err.to_string().contains("hp-gl"), "{err}");
    }

    #[test]
    fn a_truncated_file_does_not_panic() {
        for cut in 0..FIXTURE.len() {
            let _ = render_plt(&FIXTURE[..cut]);
        }
    }

    #[test]
    fn an_empty_file_is_declined() {
        let err = render_plt(b"").unwrap_err();
        assert!(err.to_string().contains("hp-gl"), "{err}");
    }

    #[test]
    fn the_pen_state_carries_the_stroke() {
        // Two `PD` runs with a `PU` between them are two polylines, not
        // one: the pen is what makes the difference.
        let out = render(b"SP1;PU0,0;PD100,0;PU200,0;PD300,0;");
        assert!(out.contains("pen 1: polyline (0,0) (100,0)"), "{out}");
        assert!(out.contains("pen 1: polyline (200,0) (300,0)"), "{out}");
    }

    #[test]
    fn relative_coordinates_move_the_pen() {
        let out = render(b"SP1;PU100,100;PD;PR50,50;");
        assert!(out.contains("pen 1: polyline (100,100) (150,150)"), "{out}");
    }

    #[test]
    fn a_circle_reports_its_centre_and_radius() {
        let out = render(b"SP1;PU500,500;CI100;");
        assert!(
            out.contains("pen 1: circle centre (500,500) radius 100"),
            "{out}"
        );
    }

    #[test]
    fn the_label_terminator_is_honoured() {
        // The default terminator is ETX; a file that says otherwise is
        // taken at its word.
        let out = render(b"SP1;PU10,20;DT!;LBhello!;");
        assert!(out.contains("label \"hello\""), "{out}");
    }
}
