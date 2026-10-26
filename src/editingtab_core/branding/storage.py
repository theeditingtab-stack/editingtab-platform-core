"""Private, Core-owned logo storage with decoded-image validation."""

import hashlib
import warnings
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from uuid import UUID, uuid4

from PIL import Image, UnidentifiedImageError

MAX_LOGO_BYTES = 2 * 1024 * 1024
MAX_LOGO_DIMENSION = 4096
MAX_LOGO_PIXELS = 16_000_000
MEDIA_FORMATS = {
    "image/png": ("PNG", ".png"),
    "image/jpeg": ("JPEG", ".jpg"),
    "image/webp": ("WEBP", ".webp"),
}


class InvalidLogo(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedLogo:
    content: bytes
    media_type: str
    width: int
    height: int
    content_sha256: str
    suffix: str


@dataclass(frozen=True)
class StoredLogo:
    key: str


def validate_logo(content: bytes, media_type: str) -> ValidatedLogo:
    expected = MEDIA_FORMATS.get(media_type)
    if expected is None or not content or len(content) > MAX_LOGO_BYTES:
        raise InvalidLogo("invalid logo")
    expected_format, suffix = expected
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as image:
                if image.format != expected_format:
                    raise InvalidLogo("invalid logo")
                width, height = image.size
                if (
                    width < 1
                    or height < 1
                    or width > MAX_LOGO_DIMENSION
                    or height > MAX_LOGO_DIMENSION
                    or width * height > MAX_LOGO_PIXELS
                ):
                    raise InvalidLogo("invalid logo")
                image.verify()
            with Image.open(BytesIO(content)) as decoded:
                decoded.load()
    except (InvalidLogo, UnidentifiedImageError, OSError, SyntaxError, ValueError, Warning):
        raise InvalidLogo("invalid logo") from None
    return ValidatedLogo(
        content=content,
        media_type=media_type,
        width=width,
        height=height,
        content_sha256=hashlib.sha256(content).hexdigest(),
        suffix=suffix,
    )


class LocalBrandingStorage:
    """Dedicated persistent filesystem boundary; replaceable by an object-store adapter."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def save(self, *, organization_id: UUID, logo: ValidatedLogo) -> StoredLogo:
        key = f"{organization_id}/{uuid4().hex}{logo.suffix}"
        target = self._target(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(f"{target.suffix}.tmp-{uuid4().hex}")
        try:
            temporary.write_bytes(logo.content)
            temporary.replace(target)
        except OSError:
            temporary.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        return StoredLogo(key=key)

    def read(self, key: str) -> bytes:
        return self._target(key).read_bytes()

    def delete(self, key: str) -> None:
        try:
            self._target(key).unlink(missing_ok=True)
        except OSError:
            pass

    def _target(self, key: str) -> Path:
        target = (self.root / key).resolve()
        if self.root not in target.parents:
            raise InvalidLogo("invalid logo")
        return target
