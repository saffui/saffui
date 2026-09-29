//! A link drawn as a QR code, in SVG a page shows as an image.

/// `text` as a scannable SVG. The image paints its own light ground, so it
/// stays readable on a dark page. `None` for a text longer than a QR code
/// holds, which no link this server writes is.
pub fn draw_qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(176, 176)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    /// The image is real SVG carrying its own light ground, so a page can hand
    /// it to an `img` untouched and it scans on a dark theme; a text past what
    /// a QR code holds draws nothing.
    #[test]
    fn a_link_becomes_a_scannable_image() {
        let drawn = super::draw_qr_svg(
            "otpauth://totp/main:ada?secret=JBSWY3DPEHPK3PXP&issuer=main\
             &algorithm=SHA1&digits=6&period=30",
        )
        .expect("a link this short always fits");
        assert!(
            drawn.starts_with("<?xml") || drawn.starts_with("<svg"),
            "{drawn}"
        );
        assert!(
            drawn.contains("#ffffff"),
            "the light ground is the image's own"
        );
        assert_eq!(super::draw_qr_svg(&"a".repeat(8_000)), None);
    }
}
