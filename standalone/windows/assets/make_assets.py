"""
Regenerates the installer artwork (secretshield.ico, wizard-large.bmp,
wizard-small.bmp). Developer tool only: needs Pillow (``pip install pillow``),
which is NOT a dependency of SecretShield or of the build. The generated
files are committed, so building the installer never needs Pillow.

The artwork is a deliberately plain shield mark and wordmark. Replace the
three files with real branding whenever you have it; nothing else depends on
how they look.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
NAVY, BLUE, WHITE, INK, GREY = "#16324F", "#1F4A75", "#FFFFFF", "#16324F", "#5B6B7B"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def shield(size: int, background=None) -> Image.Image:
    """The shield mark, drawn 4x oversampled then reduced for smooth edges."""
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), background or (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def pts(points):
        return [(x / 256 * s, y / 256 * s) for x, y in points]

    outline = [(128, 10), (226, 42), (226, 118), (208, 176), (128, 246), (48, 176), (30, 118), (30, 42)]
    inner = [(128, 30), (208, 56), (208, 116), (194, 164), (128, 224), (62, 164), (48, 116), (48, 56)]
    d.polygon(pts(outline), fill=NAVY)
    d.polygon(pts(inner), fill=BLUE)
    cx, cy, r = 128 / 256 * s, 104 / 256 * s, 24 / 256 * s
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=WHITE)  # keyhole head
    d.polygon(pts([(114, 112), (142, 112), (150, 168), (106, 168)]), fill=WHITE)  # keyhole stem
    return img.resize((size, size), Image.LANCZOS)


def write_icon() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    shield(256).save(HERE / "secretshield.ico", sizes=[(n, n) for n in sizes])


def write_wizard_large() -> None:
    w, h = 164, 314
    img = Image.new("RGB", (w, h), "#F4F7FA")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 6], fill=NAVY)
    mark = shield(104, background=(244, 247, 250, 255)).convert("RGB")
    img.paste(mark, ((w - 104) // 2, 40))
    title = ImageFont.truetype(BOLD, 19)
    small = ImageFont.truetype(REGULAR, 11)
    d.text((w / 2, 168), "SecretShield", font=title, fill=INK, anchor="mm")
    for i, line in enumerate(["Stop secrets", "before they leak."]):
        d.text((w / 2, 194 + i * 15), line, font=small, fill=GREY, anchor="mm")
    img.save(HERE / "wizard-large.bmp", format="BMP")


def write_wizard_small() -> None:
    img = Image.new("RGB", (55, 55), WHITE)
    img.paste(shield(47, background=(255, 255, 255, 255)).convert("RGB"), (4, 4))
    img.save(HERE / "wizard-small.bmp", format="BMP")


if __name__ == "__main__":
    write_icon()
    write_wizard_large()
    write_wizard_small()
    print("wrote", ", ".join(p.name for p in sorted(HERE.glob("*.[ib][cm][op]"))))
