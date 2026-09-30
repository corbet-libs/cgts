//! Adapters delegate execution and cryptography to the existing leaves.
use crate::*;

fn description(gate: &str, provider: &str, text: &str, input: &str) -> Descriptor {
    Descriptor {
        gate: gate.into(),
        provider: provider.into(),
        level: GateLevel::Community,
        steps: vec![Step {
            id: "submit".into(),
            description: text.into(),
            input: input.into(),
        }],
    }
}

/// Voucher gate with a server-authorized sponsor verification key. Never accept
/// this configuration from the redeeming member; the provider names the voucher
/// service, not the sponsor. No key or voucher is stored by cgts.
pub struct VoucherGate {
    provider: String,
    sponsor: ed25519_dalek::VerifyingKey,
}

impl VoucherGate {
    /// The service checks sponsorship authority before choosing this key.
    pub fn new(provider: impl Into<String>, sponsor: ed25519_dalek::VerifyingKey) -> Result<Self> {
        let provider = provider.into();
        component(&provider)?;
        Ok(Self { provider, sponsor })
    }
}

impl Gate for VoucherGate {
    type Input = cvch::Voucher;
    fn descriptor(&self) -> Descriptor {
        description(
            "cvch",
            &self.provider,
            "Present a member voucher.",
            "cvch.Voucher",
        )
    }
    async fn verify(&self, context: Context<'_>, voucher: &Self::Input) -> Result<Proof> {
        let now = context.now.try_into().map_err(|_| Error::Invalid)?;
        cvch::verify(voucher, &self.sponsor, &context.snapshot.community, now)
            .map_err(|_| Error::Refused)?;
        let expiry = voucher.valid_until.try_into().map_err(|_| Error::Refused)?;
        // cvch explicitly delegates durable first-claim-wins storage to its host.
        // Verification and receipt hashing stay entirely in the leaf.
        let claim = Claim::new("cvch", cvch::receipt_id(&voucher.id).into_bytes())?;
        Ok(Proof::retained(expiry).with_claim(claim))
    }
}

/// Profile gate using cgrd's authenticated bundle and signed snapshots. The
/// configured scope is a minimum: a public-only check cannot assert full validity.
pub struct ProfileGate<'a> {
    /// Provider identifier from trusted service configuration.
    pub provider: &'a str,
    /// Verifier-owned keys, time, revision/epoch floors and signed settings.
    pub policy: cgrd::Policy<'a>,
    /// Signed schema, authenticated inside cgrd.
    pub schema: &'a [u8],
    /// Required profile projection.
    pub scope: cgrd::Scope,
}

impl Gate for ProfileGate<'_> {
    type Input = cgrd::Bundle;
    fn descriptor(&self) -> Descriptor {
        description(
            "cgrd",
            self.provider,
            "Present the signed profile and required pin openings.",
            "cgrd.Bundle",
        )
    }
    async fn verify(&self, context: Context<'_>, bundle: &Self::Input) -> Result<Proof> {
        if self.policy.community != context.snapshot.community
            || self.policy.now != u64::try_from(context.now).map_err(|_| Error::Invalid)?
            || self.policy.minimum_epoch < context.snapshot.policy_epoch
        {
            return Err(Error::Scope);
        }
        match cgrd::check(bundle, &self.policy, self.schema) {
            cgrd::Admission::Admitted {
                community,
                member,
                scope,
                ..
            } if community == context.snapshot.community
                && member == context.subject
                && (scope == cgrd::Scope::Full || self.scope == cgrd::Scope::Public) =>
            {
                // Leaf success is current at this second only. Do not turn profile
                // validity into a stored badge that outlives edits or revocations.
                Ok(Proof::transient(
                    context.now.checked_add(1).ok_or(Error::Invalid)?,
                ))
            }
            _ => Err(Error::Refused),
        }
    }
}

/// Transient issuer acceptance of an extended change spend. No balance, hidden
/// witness, proof or acceptance is stored by cgts.
pub struct ChangeSpend {
    /// Complete cblc request bound into the issuer's acceptance.
    pub request: cblc::accounting::AccountRequest,
    /// Verified issuer response, still untrusted until the leaf checks it.
    pub acceptance: cblc::accounting::AccountAcceptance,
    /// Exact extended effect and inbox supplied to the issuer.
    pub update: cblc::extensions::ExtendedUpdate,
}

/// Balance-as-gate adapter for cblc's signed, single-use change permissions.
/// Configuration is trusted and must be bound to the actual pending field edit.
/// The issuer must activate a complete extension verifier; cgts never substitutes
/// ordinary v2 acceptance or a signature for the hidden balance relation.
pub struct BalanceGate<'a> {
    /// Configured provider.
    pub provider: &'a str,
    /// Community name corresponding to the configured opaque accounting scope.
    pub community: &'a str,
    /// Authenticated community pseudonym corresponding to `owner`.
    pub subject: &'a str,
    /// Exact operation authorized by this field change.
    pub action: &'a str,
    /// Opaque accounting community ID selected by the service.
    pub accounting_community: [u8; 32],
    /// Opaque accounting owner bound by the service to `subject`.
    pub owner: [u8; 32],
    /// Nonzero opaque commitment to the exact pending field edit, computed by a leaf.
    pub binding: [u8; 32],
    /// Authenticated cblc issuer public key.
    pub operator_key: [u8; 32],
    /// Pinned complete extension circuit and verification key.
    pub proof_scope: cblc::accounting::AccountProofScope,
    /// Immutable extension policy, supplied by the service.
    pub policy: &'a cblc::extensions::ExtensionPolicy,
}

impl Gate for BalanceGate<'_> {
    type Input = ChangeSpend;
    fn descriptor(&self) -> Descriptor {
        description(
            "cblc",
            self.provider,
            "Present an issuer-approved change-token spend for this field edit.",
            "cblc.ChangeSpend",
        )
    }
    async fn verify(&self, context: Context<'_>, input: &Self::Input) -> Result<Proof> {
        let now = u64::try_from(context.now).map_err(|_| Error::Invalid)?;
        let request = &input.request;
        let statement = &request.statement;
        if context.snapshot.community != self.community
            || context.subject != self.subject
            || context.action != self.action
            || statement.community != self.accounting_community
            || statement.owner != self.owner
            || self.binding == [0; 32]
            || input.update.effect
                != (cblc::extensions::Effect::Change {
                    binding: self.binding,
                })
            || statement.genesis
            || statement.settlement_marker == [0; 32]
            || request.proof_scope != self.proof_scope
            || request.issued_at > now
            || request.expires_at <= now
            || statement.valid_until <= now
            || input.acceptance.accepted_at > now
        {
            return Err(Error::Refused);
        }
        cblc::extensions::verify_extended_acceptance(
            &input.acceptance,
            request,
            &input.update,
            self.policy,
            &self.operator_key,
        )
        .map_err(|_| Error::Refused)?;
        // The marker alone is deliberately not associated with an owner or time.
        let claim = Claim::new("cblc-change", statement.settlement_marker.to_vec())?;
        let expiry = statement
            .valid_until
            .min(request.expires_at)
            .try_into()
            .map_err(|_| Error::Refused)?;
        Ok(Proof::transient(expiry).with_claim(claim))
    }
}

/// Development-only global toy gate. This module and its always-pass behavior
/// are absent whenever debug assertions are disabled (including release builds).
#[cfg(debug_assertions)]
pub mod development {
    use super::*;

    /// Explicit toy-model global check. The global service owns the holder scope;
    /// cgts never persists this result in a community database.
    pub fn global(subject: &str, now: i64, valid_until: i64) -> Result<GateResult> {
        identifier(subject)?;
        if now < 0 || valid_until <= now {
            return Err(Error::Invalid);
        }
        Ok(GateResult {
            gate: "development-test".into(),
            level: GateLevel::Global,
            subject: subject.into(),
            provider: "development".into(),
            valid_until,
        })
    }

    /// Headless description for the global toy service.
    pub fn descriptor() -> Descriptor {
        let mut result = description(
            "development-test",
            "development",
            "Complete the development-only test gate.",
            "unit",
        );
        result.level = GateLevel::Global;
        result
    }
}

/// Public-record proof supplied transiently to the balance leaf. Below-quorum
/// records still require a proof; no raw counters are accepted or retained.
pub struct RecordProof {
    /// Opaque current-state binding and optional relative shares.
    pub record: cblc::extensions::PublicRecord,
    /// Complete extension proof, checked only by the configured leaf verifier.
    pub proof: Vec<u8>,
}

/// cblc's required fresh record gate for forum listing and first contact.
/// The service selects the ledger, authenticated owner and expected challenge;
/// request data cannot select them. Run inside a Tokio runtime.
/// Construct and drop a standalone ledger's last owner on a blocking thread;
/// prefer a service-owned crlt capability/runtime when composing storage.
pub struct RecordGate<'a, V: cblc::accounting::AccountProofVerifier> {
    /// Configured provider.
    pub provider: &'a str,
    /// Community corresponding to the configured issuer ledger.
    pub community: &'a str,
    /// Authenticated pseudonym corresponding to `owner`.
    pub subject: &'a str,
    /// Exact service action corresponding to `expected.purpose`.
    pub action: &'a str,
    /// Community accounting owner, selected independently of member input.
    pub owner: [u8; 32],
    /// Relying-service challenge, intended use and exclusive expiry.
    pub expected: cblc::extensions::RecordContext,
    /// Existing cblc issuer with a complete extension verifier configured.
    pub ledger: std::sync::Arc<std::sync::Mutex<cblc::accounting_ledger::AccountLedger<V>>>,
    /// Trusted clock, also checked after the blocking proof operation.
    pub clock: std::sync::Arc<dyn clbs::Clock>,
}

impl<V: cblc::accounting::AccountProofVerifier + Send + 'static> Gate for RecordGate<'_, V> {
    type Input = RecordProof;
    fn descriptor(&self) -> Descriptor {
        description(
            "cblc",
            self.provider,
            "Prove the current balance record for this action and challenge.",
            "cblc.RecordProof",
        )
    }
    async fn verify(&self, context: Context<'_>, input: &Self::Input) -> Result<Proof> {
        if context.snapshot.community != self.community
            || context.subject != self.subject
            || context.action != self.action
            || self.clock.now().map_err(|_| Error::Invalid)? != context.now
        {
            return Err(Error::Scope);
        }
        // Cap transport-level copies; cblc enforces its configured proof bound too.
        if input.proof.is_empty() || input.proof.len() > 1024 * 1024 {
            return Err(Error::Refused);
        }
        let ledger = self.ledger.clone();
        let record = input.record.clone();
        let proof = input.proof.clone();
        let expected = self.expected.clone();
        let owner = self.owner;
        let clock = self.clock.clone();
        let until = i64::try_from(expected.expires_at).map_err(|_| Error::Invalid)?;
        tokio::task::spawn_blocking(move || {
            ledger
                .lock()
                .map_err(|_| Error::Storage)?
                .check_record(owner, &expected, &record, &proof, || {
                    clock
                        .now()
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .unwrap_or(u64::MAX)
                })
                .map_err(|_| Error::Refused)?;
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| Error::Refused)??;
        let completed = self.clock.now().map_err(|_| Error::Invalid)?;
        if completed < context.now || completed >= until {
            return Err(Error::Refused);
        }
        Ok(Proof::transient(until))
    }
}
