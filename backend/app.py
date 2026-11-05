"""Local API connecting the demo frontend to the existing protocol modules."""

from __future__ import annotations

import secrets
import time
from datetime import date

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from attacks.attacks import build_attacks, run_attack
from ppkyc.channel import Channel
from ppkyc.mpc.pipeline import run_pipeline
from ppkyc.oram.doram_ro import RegistryClient, RegistryServer
from ppkyc.psi.dh_psi import deduplicate_identifiers, run_psi
from ppkyc.zkp import credential as cr

app = FastAPI(
    title="Privacy-Preserving KYC Demo API",
    description="Local demonstration API; not intended for production use.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class PsiRequest(BaseModel):
    watchlist: list[str] = Field(min_length=1, max_length=50)
    customers: list[str] = Field(min_length=1, max_length=50)


class AmlRequest(BaseModel):
    banks: list[list[int]] = Field(min_length=1, max_length=3)
    weights: list[int] = Field(min_length=1, max_length=3)
    threshold: int = Field(ge=0, le=(1 << 16) - 1)


class RegistryRequest(BaseModel):
    records: list[int] = Field(min_length=1, max_length=128)
    index: int = Field(ge=0)


class CredentialRequest(BaseModel):
    dob: int = Field(ge=19000101, le=20261106)
    nationality: int = Field(ge=0, le=999)
    kyc_level: int = Field(ge=0, le=15)
    relying_party: str = Field(default="demo-bank", min_length=1, max_length=64)


class AttackRunRequest(BaseModel):
    system: str = Field(pattern="^(v0|v1)$")
    candidate_ids: list[str] = Field(default_factory=list, max_length=100)
    amount: int = Field(default=5000, ge=0, le=10000)
    attempts: int = Field(default=5, ge=1, le=25)
    range_start: int = Field(default=7000, ge=0, le=999999)
    range_count: int = Field(default=3000, ge=1, le=10000)


ATTACK_GUIDES = [
    {
        "number": 1,
        "name": "PII database breach",
        "use_case": "Customer records should not be exposed if a central KYC database is compromised.",
        "what_happens": "The attacker dumps a naive database and compares the exposed fields with what a private system stores.",
        "v0": "A central database contains names, dates of birth, and identity data in readable form.",
        "v1": "The prototype check sees a hiding commitment instead of a complete customer record.",
        "defence": "Data minimization; commitments and secret shares",
        "steps": ["Compromise the demo service state.", "Inspect what data the attacker can read.", "Compare exposed fields between v0 and v1."],
        "inputs": [],
    },
    {
        "number": 2,
        "name": "Hash dictionary",
        "use_case": "Predictable identity numbers can be guessed offline when a system stores plain hashes.",
        "what_happens": "The attacker hashes candidate IDs and checks which guesses match the naive watchlist.",
        "v0": "Matching hashes reveal the corresponding candidate ID.",
        "v1": "DH-PSI applies a secret exponent, so an ordinary hash guess does not match the protected group element.",
        "defence": "DH-PSI with secret exponents",
        "steps": ["Enter candidate IDs the attacker will guess.", "Hash each candidate against the naive watchlist.", "Compare with DH-protected watchlist values."],
        "inputs": [{"name": "candidate_ids", "label": "Attacker's candidate IDs", "type": "textarea", "default": "ID-1001\nID-9999", "help": "One fictional ID per line. ID-9999 is included in the demo watchlist."}],
    },
    {
        "number": 3,
        "name": "Non-group hash leakage",
        "use_case": "A PSI encoding must not expose algebraic relationships between identifiers.",
        "what_happens": "The demo contrasts structurally transparent integer hashing with the project's hash-to-group operation.",
        "v0": "Integer hashing preserves a multiplicative relation that the illustrative attacker can detect.",
        "v1": "Cofactor-cleared subgroup elements do not expose that integer ratio relation.",
        "defence": "Hash identifiers into the prime-order group",
        "steps": ["Hash sample identifiers as ordinary integers.", "Check the algebraic relation in the naive construction.", "Repeat with subgroup hash-to-group elements."],
        "inputs": [],
    },
    {
        "number": 4,
        "name": "Amount snooping",
        "use_case": "Banks should jointly compute a risk flag without giving a central service their raw balances.",
        "what_happens": "A server inspects one bank's amount in the naive service and a random additive share in the private demo.",
        "v0": "The risk engine receives the raw amount.",
        "v1": "A single server sees a random share, not the original amount.",
        "defence": "Additive secret sharing and garbled-circuit comparison",
        "steps": ["Choose a fictional amount to inspect.", "Give the naive risk engine its raw value.", "Split the value into random shares and inspect one share."],
        "inputs": [{"name": "amount", "label": "Fictional bank amount", "type": "number", "default": 5000, "help": "Choose a value from 0 to 10,000."}],
    },
    {
        "number": 5,
        "name": "Access-pattern inference",
        "use_case": "A cloud host should not infer which customer record is accessed from repeated reads.",
        "what_happens": "A skewed read workload is logged directly in v0 and passed through a square-root ORAM in v1.",
        "v0": "Repeated physical accesses reveal the popular logical record.",
        "v1": "The ORAM permutes records and hides the logical index from the observed trace.",
        "defence": "Oblivious RAM access patterns",
        "steps": ["Generate a skewed sequence of logical record reads.", "Inspect the naive physical access log.", "Compare with the ORAM's permuted physical trace."],
        "inputs": [],
    },
    {
        "number": 6,
        "name": "Malicious OT receiver",
        "use_case": "An OT receiver should learn only its selected input, not both alternatives.",
        "what_happens": "The demo compares independently chosen public keys with the Naor-Pinkas key relation.",
        "v0": "A receiver that knows both key exponents can decrypt both messages.",
        "v1": "The receiver obtains its chosen message; learning the other requires the sender's secret exponent.",
        "defence": "Naor-Pinkas constrains the receiver's keys",
        "steps": ["The sender prepares two alternative secret messages.", "Try the unconstrained two-key receiver.", "Use the constrained OT and check what the receiver learns."],
        "inputs": [],
    },
    {
        "number": 7,
        "name": "Nonce reuse",
        "use_case": "Proof and signature randomness must be fresh; reusing a Schnorr nonce can expose a secret key.",
        "what_happens": "The attacker applies the special-soundness extractor to two transcripts that reuse one commitment.",
        "v0": "Two accepting transcripts reveal the signing witness when the nonce is reused.",
        "v1": "Fresh proof nonces produce different commitments, so this paired-transcript extraction does not apply.",
        "defence": "Fresh random nonces",
        "steps": ["Create two transcripts that reuse one nonce.", "Extract the witness from the two responses.", "Compare with two fresh independently randomized proofs."],
        "inputs": [],
    },
    {
        "number": 8,
        "name": "Short-challenge forgery",
        "use_case": "Fiat-Shamir challenges must be sufficiently large to make proof guessing infeasible.",
        "what_happens": "The demo searches for an accepting Schnorr transcript under a deliberately tiny challenge space.",
        "v0": "The short challenge permits a practical transcript-guessing demonstration.",
        "v1": "The production-sized challenge makes the same search infeasible; the demo models this with a bounded search.",
        "defence": "Full-length Fiat-Shamir challenges",
        "steps": ["Pick a proof response without knowing the witness.", "Search for a matching 10-bit challenge.", "Explain why the same search is infeasible at full challenge length."],
        "inputs": [],
    },
    {
        "number": 9,
        "name": "Cross-party replay",
        "use_case": "A valid presentation for one relying party must not be replayable to another.",
        "what_happens": "The attacker reuses a bearer-style proof at another relying party and compares it with a context-bound proof.",
        "v0": "A bearer proof has no relying-party binding and is accepted by the second party.",
        "v1": "The proof transcript includes relying-party context and fails verification under a different party.",
        "defence": "Relying-party and nonce binding",
        "steps": ["Capture a proof or bearer token at Bank A.", "Replay it to Bank B in the naive flow.", "Verify a context-bound proof under Bank B's identity."],
        "inputs": [],
    },
    {
        "number": 10,
        "name": "Credential lending",
        "use_case": "A credential should prove its legitimate holder is presenting it.",
        "what_happens": "Bob attempts to use Alice's credential without knowing the secret key committed inside it.",
        "v0": "A document or bearer credential can be presented by another person.",
        "v1": "The presentation proof must demonstrate knowledge of the holder secret linked to the signed commitment.",
        "defence": "Secret-key holder binding",
        "steps": ["Issue a credential bound to Alice's secret.", "Have Bob copy the signed credential.", "Check whether Bob can prove knowledge of Alice's secret."],
        "inputs": [],
    },
    {
        "number": 11,
        "name": "Sybil account creation",
        "use_case": "One credential holder should not create multiple accounts at the same relying party.",
        "what_happens": "The attacker makes repeated account attempts using the same identity.",
        "v0": "Bearer-style account creation accepts each attempt.",
        "v1": "A relying party recognizes the repeated scoped nullifier and rejects duplicate attempts.",
        "defence": "Per-relying-party nullifier",
        "steps": ["Choose how many account attempts to make.", "Open accounts without a uniqueness check in v0.", "Use one scoped nullifier per credential at the protected relying party."],
        "inputs": [{"name": "attempts", "label": "Account creation attempts", "type": "number", "default": 5, "help": "Choose between 1 and 25 attempts."}],
    },
    {
        "number": 12,
        "name": "PSI query enumeration",
        "use_case": "A legitimate PSI client can still abuse repeated queries to discover a watchlist.",
        "what_happens": "The attacker searches a chosen identifier range; v1 limits each query window but cannot cryptographically eliminate enumeration.",
        "v0": "An unrestricted dictionary search can recover watchlist entries in the selected range.",
        "v1": "Only the first 100 demo queries are allowed; enumeration remains a documented residual risk.",
        "defence": "Query cap, authentication, and audit (partial mitigation)",
        "steps": ["Choose a starting ID and search-range size.", "Search the whole range against the naive hashed watchlist.", "Apply the query-window cap and observe that this is mitigation, not a complete fix."],
        "inputs": [
            {"name": "range_start", "label": "Starting ID number", "type": "number", "default": 7000, "help": "IDs are generated as ID-number."},
            {"name": "range_count", "label": "Number of IDs to try", "type": "number", "default": 3000, "help": "Choose between 1 and 10,000 candidates."},
        ],
    },
    {
        "number": 13,
        "name": "Invalid-group input",
        "use_case": "Verifiers must reject group elements outside the expected prime-order subgroup.",
        "what_happens": "The demo submits an order-2 element to a verifier with and without subgroup validation.",
        "v0": "An unchecked verifier accepts an element that is not in the expected subgroup.",
        "v1": "The group-membership check rejects the invalid element before it is used.",
        "defence": "Validate every received group element",
        "steps": ["Construct an element outside the expected subgroup.", "Pass it to the naive verifier without validation.", "Check subgroup membership and reject it in v1."],
        "inputs": [],
    },
]


def _validate_text_items(values: list[str], label: str) -> None:
    if any(not value.strip() for value in values):
        raise HTTPException(status_code=422, detail=f"{label} entries cannot be blank.")
    if any(len(value) > 160 for value in values):
        raise HTTPException(status_code=422, detail=f"{label} entries must be 160 characters or fewer.")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "Privacy-Preserving KYC Demo API"}


@app.post("/api/psi")
def sanctions_screening(request: PsiRequest) -> dict:
    _validate_text_items(request.watchlist, "Watchlist")
    _validate_text_items(request.customers, "Customer")
    watchlist = deduplicate_identifiers(request.watchlist)
    customers = deduplicate_identifiers(request.customers)
    channel = Channel()
    matches = run_psi(request.watchlist, request.customers, channel)
    return {
        "matches": matches,
        "customer_count": len(customers),
        "watchlist_size": len(watchlist),
        "duplicate_customers_ignored": len(request.customers) - len(customers),
        "duplicate_watchlist_entries_ignored": len(request.watchlist) - len(watchlist),
        "protocol_messages": channel.rounds(),
        "communication_bytes": channel.total_bytes(),
        "privacy_note": "Only the bank's matching customer identifiers are returned.",
    }


@app.post("/api/aml")
def aml_analytics(request: AmlRequest) -> dict:
    dimension = len(request.weights)
    if any(len(bank) != dimension for bank in request.banks):
        raise HTTPException(
            status_code=422,
            detail="Each bank must provide one feature for every model weight.",
        )
    if any(value < 0 or value > 10000 for bank in request.banks for value in bank):
        raise HTTPException(status_code=422, detail="Bank features must be between 0 and 10000.")
    if any(weight < 0 or weight > 100 for weight in request.weights):
        raise HTTPException(status_code=422, detail="Model weights must be between 0 and 100.")
    if request.threshold < 0:
        raise HTTPException(status_code=422, detail="Threshold must be non-negative.")
    maximum_score = sum(
        weight * sum(bank[index] for bank in request.banks)
        for index, weight in enumerate(request.weights)
    )
    if maximum_score >= (1 << 16):
        raise HTTPException(
            status_code=422,
            detail="Combined weighted score must fit in the demo's 16-bit comparison range.",
        )

    channel = Channel()
    result = run_pipeline(
        request.banks,
        request.weights,
        threshold=request.threshold,
        bits=16,
        channel=channel,
    )
    return {
        "flag": bool(result["flag"]),
        "threshold": request.threshold,
        "protocol_messages": channel.rounds(),
        "communication_bytes": channel.total_bytes(),
        "privacy_note": "The frontend receives only the threshold flag, not the reconstructed score.",
    }


@app.post("/api/registry")
def private_registry_read(request: RegistryRequest) -> dict:
    if not 0 <= request.index < len(request.records):
        raise HTTPException(status_code=422, detail="Record index is outside the registry.")
    if any(value < 0 or value > 3 for value in request.records):
        raise HTTPException(status_code=422, detail="Registry statuses must be between 0 and 3.")

    s0 = RegistryServer("S0", request.records)
    s1 = RegistryServer("S1", request.records)
    channel = Channel()
    value = RegistryClient(s0, s1).read(request.index, channel)
    return {
        "status_code": value,
        "status_label": {0: "Not verified", 1: "Basic", 2: "Enhanced", 3: "Fully verified"}[value],
        "registry_size": len(request.records),
        "protocol_messages": channel.rounds(),
        "communication_bytes": channel.total_bytes(),
        "privacy_note": "Each server receives a random share of the query, not the requested index.",
    }


@app.post("/api/credential")
def verify_credential(request: CredentialRequest) -> dict:
    today = int(date.today().strftime("%Y%m%d"))
    if request.dob > today:
        raise HTTPException(status_code=422, detail="Date of birth cannot be in the future.")

    issuer = cr.Issuer("demo-issuer")
    wallet = cr.Wallet(
        dob=request.dob,
        nationality=request.nationality,
        kyc_level=request.kyc_level,
    )
    expected = {
        "dob": request.dob,
        "nat": request.nationality,
        "level": request.kyc_level,
    }
    credential = cr.issue(
        issuer,
        wallet.issuance_request(),
        expiry=20301231,
        expected=expected,
    )
    wallet.store_credential(credential)

    predicates = cr.Predicates(min_age=18, allowed_nats=[1, 44, 91], min_level=2)
    relying_party = cr.RelyingParty(request.relying_party, issuer.ipk)
    presentation_request = cr.PresentationRequest(
        rp_id=request.relying_party,
        nonce=secrets.token_bytes(16),
        timestamp=int(time.time()),
        today=today,
        predicates=predicates,
    )
    try:
        presentation = cr.present(wallet, presentation_request)
    except ValueError as exc:
        return {
            "accepted": False,
            "reason": str(exc),
            "privacy_note": "The proof was rejected; raw attributes are not returned.",
        }

    accepted = relying_party.verify(presentation, presentation_request)
    return {
        "accepted": accepted,
        "proof_generated": True,
        "relying_party": request.relying_party,
        "privacy_note": "The relying party learns the predicate result, not the date of birth.",
    }


@app.get("/api/attacks/catalog")
def attack_catalog() -> dict:
    return {"attacks": ATTACK_GUIDES}


@app.post("/api/attacks/{attack_number}")
def run_attack_demo(attack_number: int, request: AttackRunRequest) -> dict:
    if not any(item["number"] == attack_number for item in ATTACK_GUIDES):
        raise HTTPException(status_code=404, detail="Unknown attack scenario.")
    if any(not item.strip() or len(item) > 80 for item in request.candidate_ids):
        raise HTTPException(status_code=422, detail="Candidate IDs must be 1–80 non-blank characters.")
    parameters = {
        "candidate_ids": request.candidate_ids or None,
        "amount": request.amount,
        "attempts": request.attempts,
        "range_start": request.range_start,
        "range_count": request.range_count,
    }
    try:
        outcome = run_attack(attack_number, request.system, **parameters)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    guide = next(item for item in ATTACK_GUIDES if item["number"] == attack_number)
    if request.system == "v0":
        interpretation = (
            "The attack succeeded against the intentionally vulnerable baseline."
            if outcome.success
            else "This attempt did not succeed against the baseline."
        )
    else:
        interpretation = (
            "Residual risk: this attack still succeeds or is only partially mitigated."
            if outcome.success
            else "The attack was blocked by the prototype's stated defense."
        )
    return {
        "number": attack_number,
        "name": guide["name"],
        "system": request.system,
        "attack_succeeded": outcome.success,
        "metric": outcome.metric,
        "evidence": outcome.evidence,
        "interpretation": interpretation,
        "defence": guide["defence"],
    }


@app.post("/api/attacks")
def attack_lab() -> dict:
    results = []
    for attack in build_attacks():
        run_v0 = attack.run_v0
        run_v1 = attack.run_v1
        if not callable(run_v0) or not callable(run_v1):
            raise TypeError(f"Attack {attack.number} does not expose callable v0/v1 runners.")
        outcome_v0 = run_v0()
        outcome_v1 = run_v1()
        results.append(
            {
                "number": attack.number,
                "name": attack.name,
                "v0_success": outcome_v0.success,
                "v0_metric": outcome_v0.metric,
                "v1_success": outcome_v1.success,
                "v1_metric": outcome_v1.metric,
                "defence": attack.defence,
                "evidence": outcome_v1.evidence,
            }
        )
    return {"attacks": results}
