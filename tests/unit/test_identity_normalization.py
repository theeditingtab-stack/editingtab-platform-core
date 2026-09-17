import pytest

from editingtab_core.identity.errors import InvalidIdentity
from editingtab_core.identity.normalization import clean_name, normalize_email, normalize_slug


def test_email_normalization_preserves_dots_plus_and_original_case():
    assert normalize_email("  Alice.Safari+Desk@Example.COM  ") == (
        "Alice.Safari+Desk@Example.COM",
        "alice.safari+desk@example.com",
    )
    assert (
        normalize_email("alice.safari+desk@example.com")[1]
        != normalize_email("alicesafari@example.com")[1]
    )


def test_slug_and_name_normalization():
    assert normalize_slug("  Safari-Lodge-2 ") == "safari-lodge-2"
    assert clean_name(" The Editing Tab ") == "The Editing Tab"


@pytest.mark.parametrize(
    "email",
    [
        "",
        "missing-at",
        "@example.com",
        "a@",
        "a@@b",
        "a b@c",
        "a\n@b",
        "caf\u00e9@example.com",
        "a" * 255 + "@b",
    ],
)
def test_unsupported_email_is_rejected_without_echo(email):
    with pytest.raises(InvalidIdentity) as error:
        normalize_email(email)
    assert str(error.value) == "A supported email address is required."


@pytest.mark.parametrize(
    "slug", ["", "two words", "-leading", "trailing-", "two--hyphens", "x" * 64]
)
def test_invalid_slug(slug):
    with pytest.raises(InvalidIdentity):
        normalize_slug(slug)


@pytest.mark.parametrize("name", [" ", "name\nline", "x" * 201])
def test_invalid_name(name):
    with pytest.raises(InvalidIdentity):
        clean_name(name)
