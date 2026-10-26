from io import BytesIO
from uuid import uuid4

import pytest
from PIL import Image

from editingtab_core.branding.services import InvalidBranding, normalize_color
from editingtab_core.branding.storage import (
    MAX_LOGO_BYTES,
    InvalidLogo,
    LocalBrandingStorage,
    validate_logo,
)


def image_bytes(image_format="PNG", size=(32, 24)):
    output = BytesIO()
    Image.new("RGB", size, color=(20, 80, 40)).save(output, format=image_format)
    return output.getvalue()


@pytest.mark.parametrize("value", ["#183C2B", "#FFFFFF", "#000000"])
def test_normalized_theme_colors_are_accepted(value):
    assert normalize_color(value) == value


@pytest.mark.parametrize(
    "value",
    ["#183c2b", "183C2B", "#FFF", "#12345678", "red", "url(https://example.test)"],
)
def test_non_normalized_or_executable_theme_values_are_rejected(value):
    with pytest.raises(InvalidBranding):
        normalize_color(value)


@pytest.mark.parametrize(
    ("image_format", "media_type"),
    [("PNG", "image/png"), ("JPEG", "image/jpeg"), ("WEBP", "image/webp")],
)
def test_logo_validation_decodes_supported_images(image_format, media_type):
    content = image_bytes(image_format)
    logo = validate_logo(content, media_type)
    assert (logo.width, logo.height) == (32, 24)
    assert logo.content == content
    assert len(logo.content_sha256) == 64


@pytest.mark.parametrize(
    ("content", "media_type"),
    [
        (b"<svg><script>alert(1)</script></svg>", "image/svg+xml"),
        (b"not-an-image", "image/png"),
        (image_bytes("PNG"), "image/jpeg"),
    ],
)
def test_logo_validation_rejects_svg_malformed_spoofed_and_oversized(content, media_type):
    with pytest.raises(InvalidLogo):
        validate_logo(content, media_type)


def test_logo_validation_rejects_oversized_content():
    with pytest.raises(InvalidLogo):
        validate_logo(b"x" * (MAX_LOGO_BYTES + 1), "image/png")


def test_logo_validation_rejects_excessive_dimensions():
    with pytest.raises(InvalidLogo):
        validate_logo(image_bytes(size=(4097, 1)), "image/png")


def test_local_branding_storage_uses_private_tenant_keys_and_blocks_traversal(tmp_path):
    storage = LocalBrandingStorage(tmp_path)
    organization_id = uuid4()
    logo = validate_logo(image_bytes(), "image/png")
    stored = storage.save(organization_id=organization_id, logo=logo)

    assert stored.key.startswith(f"{organization_id}/")
    assert storage.read(stored.key) == logo.content
    assert str(tmp_path) not in stored.key
    with pytest.raises(InvalidLogo):
        storage.read("../outside.png")

    storage.delete(stored.key)
    with pytest.raises(FileNotFoundError):
        storage.read(stored.key)
