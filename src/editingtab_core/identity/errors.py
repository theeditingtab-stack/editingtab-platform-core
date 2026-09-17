"""Safe domain errors: no submitted values, SQL, or driver diagnostics."""


class IdentityError(Exception):
    pass


class InvalidIdentity(IdentityError):
    pass


class IdentityConflict(IdentityError):
    pass


class IdentityNotFound(IdentityError):
    pass


class IdentityUnavailable(IdentityError):
    pass


class IdentityStorageError(IdentityError):
    pass
