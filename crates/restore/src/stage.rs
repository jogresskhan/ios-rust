//! Boot stage painter (logo/hello/homescreen) — renders the boot-ladder
//! frames into the vm-core framebuffer and dumps BMPs (the GUI path the
//! engine smoke uses; the ADP v4 DisplayPipe is the real scanout).

/// The boot stages the full-system ladder paints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Apple logo with the progress bar (iBoot → xnu handoff)
    Logo,
    /// "Hello" — the international greeting after SpringBoard starts
    Hello,
    /// the homescreen (G4 target)
    Homescreen,
}

/// Paint `stage` into the framebuffer and write a BMP at `path`.
/// Paint `stage` into the framebuffer and write a BMP at `path`.
pub fn paint_to_bmp(
    fb: &mut vm_core::framebuffer::FrameBuffer,
    stage: Stage,
    progress: Option<f32>,
    path: &str,
) -> Result<(), std::io::Error> {
    paint(fb, stage, progress);
    fb.sequence += 1;
    vm_core::framebuffer::write_bmp(fb, path)
}

/// Paint a stage into the framebuffer (RGBA, 2436×1125 lane geometry).
pub fn paint(fb: &mut vm_core::framebuffer::FrameBuffer, stage: Stage, progress: Option<f32>) {
    let (w, h) = (fb.width, fb.height);
    for y in 0..h {
        for x in 0..w {
            let d = ((y * w + x) * 4) as usize;
            match stage {
                Stage::Logo => {
                    fb.rgba[d] = 0;
                    fb.rgba[d + 1] = 0;
                    fb.rgba[d + 2] = 0;
                    fb.rgba[d + 3] = 0xFF;
                }
                Stage::Hello => {
                    let t = ((x * 255) / w.max(1)) as u8;
                    fb.rgba[d] = 0x10;
                    fb.rgba[d + 1] = 0x10 + t / 8;
                    fb.rgba[d + 2] = 0x30;
                    fb.rgba[d + 3] = 0xFF;
                }
                Stage::Homescreen => {
                    // wallpaper gradient + icon grid rows
                    let t = (y * 255 / h.max(1)) as u8;
                    fb.rgba[d] = 0x1A + t / 4;
                    fb.rgba[d + 1] = 0x0A + t / 6;
                    fb.rgba[d + 2] = 0x2E;
                    fb.rgba[d + 3] = 0xFF;
                }
            }
        }
    }
    match stage {
        Stage::Logo => {
            // progress bar at the bottom
            if let Some(p) = progress {
                let p = p.clamp(0.0, 1.0);
                let bw = (w as f32 * 0.5) as i64;
                let bh = 6i64;
                let bx = (w as i64 - bw) / 2;
                let by = h as i64 - 120;
                let fill = (bw as f32 * p) as i64;
                for yy in by..by + bh {
                    for xx in bx - 2..bx + bw + 2 {
                        if xx < 0 || yy < 0 || xx >= w as i64 || yy >= h as i64 {
                            continue;
                        }
                        let d = ((yy * w as i64 + xx) * 4) as usize;
                        let in_fill = xx - bx < fill;
                        fb.rgba[d] = if in_fill { 0xF5 } else { 0x30 };
                        fb.rgba[d + 1] = if in_fill { 0xF5 } else { 0x30 };
                        fb.rgba[d + 2] = if in_fill { 0xF7 } else { 0x38 };
                    }
                }
            }
        }
        Stage::Homescreen => {
            // 6×5 icon grid (rounded squares) above the dock
            let cols = 6;
            let rows = 5;
            let cw = w as i64 / cols;
            let ch = (h as i64 * 3) / 4 / rows;
            let size = (cw.min(ch) * 3) / 5;
            for r in 0..rows {
                for c in 0..cols {
                    let cx = cw * c as i64 + (cw - size) / 2;
                    let cy = ch * r as i64 + (ch - size) / 2 + 40;
                    let hue = ((r * cols + c) * 37 % 255) as u8;
                    draw_rounded_square(fb, cx, cy, size, hue);
                }
            }
            // dock
            let dock_y = h * 4 / 5;
            for y in dock_y..h {
                for x in 0..w {
                    let d = ((y * w + x) * 4) as usize;
                    fb.rgba[d] = fb.rgba[d] / 3 + 0x10;
                    fb.rgba[d + 1] = fb.rgba[d + 1] / 3 + 0x10;
                    fb.rgba[d + 2] = fb.rgba[d + 2] / 3 + 0x18;
                }
            }
        }
        Stage::Hello => {}
    }
}

fn draw_rounded_square(fb: &mut vm_core::framebuffer::FrameBuffer, x0: i64, y0: i64, size: i64, hue: u8) {
    let r = size / 5;
    for y in y0..y0 + size {
        for x in x0..x0 + size {
            if x < 0 || y < 0 || x >= fb.width as i64 || y >= fb.height as i64 {
                continue;
            }
            // rounded corners
            let (dx, dy) = (
                (x - x0).min(x0 + size - 1 - x),
                (y - y0).min(y0 + size - 1 - y),
            );
            if dx < r && dy < r && (r - dx) * (r - dx) + (r - dy) * (r - dy) > r * r {
                continue;
            }
            let d = ((y * fb.width as i64 + x) * 4) as usize;
            fb.rgba[d] = hue;
            fb.rgba[d + 1] = hue / 2 + 0x40;
            fb.rgba[d + 2] = 255 - hue;
            fb.rgba[d + 3] = 0xFF;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_all_stages_without_panic() {
        let mut fb = vm_core::framebuffer::FrameBuffer::new(240, 120);
        for (stage, prog) in [
            (Stage::Logo, Some(0.5)),
            (Stage::Logo, None),
            (Stage::Hello, None),
            (Stage::Homescreen, None),
        ] {
            paint(&mut fb, stage, prog);
        }
        assert_eq!(fb.rgba.len(), (240 * 120 * 4) as usize);
    }
}
