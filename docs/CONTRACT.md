# cgts implemented contract

cgts is the FSL community gatekeeping facade under cvld → cmnt. It runs
registered gates, collects results, and composes the mandatory community clbs
veto with crbk decisions. It does not assign trust levels. Gate and provider
switches are on/off. Crypto, profile validation, legal-order semantics, voucher
verification and private accounting stay in their existing leaves.

## Authority and API

`Gatekeeper::new(storage, legal)` requires matching community capabilities.
The service authenticates the subject, active rulebook snapshot, action, clock,
provider configuration and leaf trust roots. These are trusted Rust inputs, never
an unverified HTTP body. Selecting a store or implementing `Gate`, `Storage` or
`LegalVeto` is privileged. A wire gate result alone is not proof of verification.

`steps(context, descriptors)` returns only enabled community gates/providers.
Each description contains gate, level, provider and ordered steps with stable ID,
plain text and a leaf input type. There is no HTML, executable callback, raw
answer or provider credential. Clients can render this data in any interface.

`run(context, gate, input)` checks scope, legal veto and both exact crbk switches
before invoking the leaf. Missing, null and false switches are off. Gate IDs and
provider IDs cannot contain `/`, preventing control-key aliases. The leaf binds
its proof to the supplied context. Expiry is exclusive, nonnegative i64 Unix
seconds. Verification failures expose static errors and do not erase existing
valid evidence. The legal veto is rechecked before committing. A failed store
operation never returns a successful checked gate. There are no automatic retries.

`GateResult` has exactly `gate`, `level`, `subject`, `provider`, `valid_until`.
There is no trust score, confidence, raw evidence, login date or proof-check time.
The community binding is the storage capability/enclosing checked result, not an
extra wire field. cgts never stores global holder identities. `CheckedGate` has
private, transient community/action/revision/epoch/time bindings. `decide` accepts
it only in that exact context; serialization exposes metadata via `result()` only.

`collect` returns enabled, unexpired retained facts for the authenticated subject.
`decide` combines those with fresh checks and delegates all/any/k-of-n and missing
groups to crbk. `clbs` always applies, even if an action policy is empty or its
switch is off. Legal errors fail closed. Maximum-proof-age policies fail closed:
the agreed five-field result has no authenticated issuance time, so the crbk
adapter supplies `proven_at: None`. Gate validity is never fabricated from a
login or check timestamp. Membership state comes from the membership facade.

`withdraw` is a trusted provider/service operation removing one current fact.
It cannot remove spent markers or rearm a voucher. Disabled facts are hidden,
not deleted; reenabling an unexpired fact makes it count again. Revocation uses
explicit withdrawal. Callers control endpoint authorization.

## Leaf adapters

- `VoucherGate`: delegates signature/expiry/community checks and receipt hashing
  to cvch. The authorized sponsor key is server configuration; the provider is
  the voucher service, never the sponsor. cvch explicitly delegates atomic spend
  storage to its host. cgts claims the opaque receipt and writes the subject's
  result in one transaction. A repeated voucher, including the same member,
  fails. An invalid signature burns nothing. No voucher ID, sponsor key or
  signature is retained. This async integration uses cvch's `verify` and
  `receipt_id`, rather than trying to drive async storage from its sync callback.
- `ProfileGate`: calls cgrd on the exact signed bundle, policy and schema. Checks
  community, member, clock, epoch floor and required full/public projection.
  A full result satisfies public requirements; public cannot satisfy full.
  Results expire at the next Unix second and are never persisted: current
  profile validity cannot become a reusable credential independent of edits.
  cgrd's default contact detector fails closed for fields that need one.
- `BalanceGate`: calls cblc's `verify_extended_acceptance` for a signed change
  spend bound to the exact request, extension policy, proof scope, accounting
  community/owner and pending field commitment. It refuses ordinary updates,
  punishment effects, genesis, zero markers, expired requests and wrong bindings.
  A permanent opaque settlement marker prevents repeated consumption. The result
  is action-bound and transient; no acceptance, balance, proof or request persists.
  The service binds accounting IDs to the authenticated pseudonym and supplies
  the exact intended field-change commitment. It must coordinate consumption
  with the downstream edit; a crash after consumption may lose permission, but
  never makes a second spend possible. This is not an atomic cpns edit API.
- `LegalGate`: delegates each exact-action check to clbs with the caller's clock.
  Orders, self-bans, authority verification and administration remain in clbs.
  No cached green legal result can bypass a later order.
- `RecordGate`: calls cblc's `check_record` on a blocking Tokio thread for first
  contact or forum listing. The service independently binds the ledger, owner,
  action, intended use, challenge and expiry. cblc verifies current commitment,
  consumed punishment inbox and the full record proof; below-quorum records also
  need a proof. The facade retains neither shares nor proofs. Missing extension
  support and stale, mismatched or invalid records fail closed. The trusted clock
  is checked before and after verification. Results are transient and expire with
  the relying-service challenge. Challenge freshness is a service responsibility.
  Standalone cblc ledgers own a runtime: construct and drop their final owner on
  a blocking thread. Composed services should supply their crlt capability and
  shared runtime through the leaf's storage adapter.
- `gates::development`: global always-pass toy gate and headless description,
  guarded by `cfg(debug_assertions)`. Absent in normal release builds, with no
  Cargo feature to enable it there. It is never accepted by the community runner.
  Do not deploy debug builds as production; custom profiles must disable debug
  assertions. The global toy service supplies its own rulebook switch checks.

Other leaves can implement the typed `Gate` boundary without extending a giant
request enum. Gate implementations are server-authorized verification code, not
plugins selected or supplied by a member.

## Storage

`Storage` has `community`, `load`, atomic `commit`, and `remove`. `MemoryStore`
is a real lock-protected implementation for disposable tests. `LibsqlStore`
uses the ready crlt API; official libSQL is only reached through crlt.
The service owns the complete migration history, credentials and connection.
Append `SCHEMA` and `clbs::SCHEMA` under service-assigned version numbers.

| Table | Stored content | Primary index |
|---|---|---|
| cgts_results | Current subject/gate/provider/expiry only | community_id, subject, gate, provider |
| cgts_spent | Leaf domain and opaque one-use marker only | community_id, domain, marker |

Both tables are WITHOUT ROWID. Every query/write is index-backed and crlt
checks plans at execution. `check_query_plans` verifies all statement shapes.
Deploy one database per community; composite community keys additionally isolate
shared-file tests. A marker claim and result replacement use one immediate
transaction. SQL rollback prevents a failed result write from burning a voucher.
Replacement stores no history. Marker rows deliberately lack subjects and times.
They must survive restarts and must not be cleared while proofs can be replayed.
Raw database administration is trusted. Reads return complete results or errors;
configure crlt row limits for the service. No logs or tracing are installed.

## Validation and integration limits

GitHub Actions runs formatting, strict Clippy, real local-libSQL and memory
round trips, signed voucher/profile/issuer-acceptance vectors, policy and legal
veto cases, failure/rollback/concurrency cases, index checks and release tests.
The optional live Turso test skips unless both TURSO_URL and TURSO_TOKEN are
nonempty; use a disposable database and never put credentials in public CI.
No Cargo runs on the workstation. No registry publication.

The cblc extension contract explicitly requires a complete extension circuit
and holder implementation before activation. This adapter verifies the issuer's
signed assertion; tests do not claim to prove hidden balance constraints.
The fresh forum-listing/first-contact record API is integrated from cblc's
CI-green main revision 135333e0. Additional introduction-balance predicates and
punishment execution stay in cblc and its complete extension relation. No substitute
balance arithmetic, proof verifier or permissive default is implemented here.

cvch has no docs/CONTRACT.md at the pinned revision; its README and public Rust
API document verification and host-owned single-use storage. cgrd's pinned csgn
wire revision differs from newer csgn main; the composition root must use the
same wire revision as cgrd until upstream coordinates the upgrade. Qualified
legal-authority/passkey verification, snapshot authenticity/freshness, transport
limits, trust-root distribution and check/action concurrency belong to services.
Checks are point-in-time, not transactions spanning leaf state and external actions.
