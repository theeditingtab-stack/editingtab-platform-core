# CORE-AUTH-004 account onboarding and session lifecycle

## Existing authentication extension

This checkpoint extends the existing global Core `User`, Argon2id `PasswordCredential`, and
opaque server-side `LoginSession`. It adds no second identity store, browser JWT, passwordless
authentication, or organization-specific password. Login throttling, active-user checks,
`HttpOnly`/`SameSite=Lax` cookies, production `Secure` cookies, immediate revocation, and
unsafe-method Origin enforcement remain in force.

## Employee invitations

An invitation belongs to one organization and records a normalized target email, inviter, expiry,
lifecycle timestamps, and optional initial role IDs. Only a SHA-256 digest of its random 256-bit
URL-safe token is stored. With no outbound provider yet, the raw token is returned once in the
authenticated `201` creation response. The caller must use a confidential delivery channel and
must not log it or persist it in frontend assets.

Creation, listing, and revocation require an active session and `core.members.manage`. Initial
roles additionally require `core.roles.assign`; roles must be active in that organization and
within the actor's CORE-AUTH-002 grant ceiling. An active member conflicts. Reissue for the same
organization/email revokes and audits the prior pending invitation. Archived membership targets
are permitted. Listings never return token values or digests, and foreign resources remain
non-disclosing.

`POST /auth/invitations/accept` needs the raw token and matching email, not a session. Acceptance
locks the invitation and rechecks expiry, revocation/use state, and the inviter's current member
management and role grant authority. Replay and concurrent double acceptance therefore fail
closed. A matching existing Core user is linked without changing global identity fields,
credentials, other memberships, or platform authority. A credentialless existing identity may
set its first password; an existing credential is never replaced. A new identity requires a name
and policy-compliant password. Membership create/restore, fresh intended assignments, token
consumption, and audit are one transaction. Historical role assignments are never restored.

## Password recovery and change

`POST /auth/password/change` requires an active session, verifies the current password through the
existing Argon2id helper, applies the existing 15-to-1024-character policy, and replaces the
credential. It preserves the current session and revokes every other session.

`POST /auth/password/reset/request` returns the same accepted contract for known, unknown,
inactive, invalid, and credentialless accounts and uses the shared database source throttle. In
explicit development/test mode it includes a one-time development token for both known and
unknown addresses; the unknown value is a non-persisted decoy. Production never returns the
token. A future email adapter must receive the raw token only transiently and deliver it without
logging it; no email provider exists in this checkpoint.

Reset tokens use a distinct table and purpose from invitations. Only their SHA-256 digests are
stored. They expire, are single-use, and reissue revokes older pending records. Confirmation sets
a policy-compliant Argon2id password and revokes every session. Expired, revoked, malformed, and
replayed tokens share the same safe authentication failure.

## Session management

`GET /auth/sessions` lists only the current user's active sessions: UUID, creation, expiry, and
`current_session`. It never exposes cookie tokens or digests. `DELETE /auth/sessions/{session_id}`
revokes only an owned session and clears the cookie when it is current. `POST
/auth/sessions/revoke-all` revokes all owned sessions and clears the cookie. Logout retains its
single-current-session behavior.

## Audit, tenant boundary, and migration

Transactional `core_security_audit` rows record `invitation.created`, `invitation.revoked`,
`invitation.accepted`, `password.changed`, `password.reset`, and `sessions.revoked`. Details are
limited to identifiers, role IDs, reasons/scopes, and counts. Tokens, token digests, passwords,
hashes, and session cookie values are excluded.

Migration `0010_account_onboarding` adds invitation, invitation-role intent, reset-token, and
security-audit tables. It modifies no existing identity, credential, session, membership, role,
platform grant, or entitlement and grants no authority. Downgrade drops only the new tables and is
intended for isolated verification under the repository's destructive-migration policy.

Core users and credentials remain global while memberships and invitation management remain
tenant-scoped. Accepting an Org A invite cannot change Org B or grant platform authority. MFA,
mailbox verification/provider integration, compromised-password screening, platform recovery and
admin lifecycle, frontend flows, and organization access context remain deferred.

## HTTP contract

| Route | Proof and authorization |
| --- | --- |
| `POST/GET /organizations/{organization_id}/invitations` | Session plus `core.members.manage`; role intent also enforces assignment/grant authority. |
| `DELETE /organizations/{organization_id}/invitations/{invitation_id}` | Session plus same-organization `core.members.manage`. |
| `POST /auth/invitations/accept` | Invitation token plus matching email. |
| `POST /auth/password/change` | Active session plus current password. |
| `POST /auth/password/reset/request` | No authentication; non-disclosing response and source throttle. |
| `POST /auth/password/reset/confirm` | Reset-token proof. |
| `GET /auth/sessions` | Active session. |
| `DELETE /auth/sessions/{session_id}` | Active session; owned target only. |
| `POST /auth/sessions/revoke-all` | Active session. |

All unsafe routes require the configured exact Origin, including token-proof acceptance and reset
routes. The existing guard adds `Cache-Control: no-store` to these responses.
