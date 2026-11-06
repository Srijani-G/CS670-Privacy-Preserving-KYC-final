const API_BASE = "http://127.0.0.1:8001";

const panels = [...document.querySelectorAll(".panel")];
const navigationButtons = [...document.querySelectorAll(".nav-item")];

function openPanel(name) {
  panels.forEach((panel) => panel.classList.toggle("active", panel.id === `panel-${name}`));
  navigationButtons.forEach((button) => button.classList.toggle("active", button.dataset.panel === name));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-panel]").forEach((button) => {
  button.addEventListener("click", () => openPanel(button.dataset.panel));
});

document.querySelectorAll("[data-open]").forEach((button) => {
  button.addEventListener("click", () => openPanel(button.dataset.open));
});

function showLoading(target, message) {
  target.replaceChildren();
  const state = document.createElement("div");
  state.className = "loading";
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  spinner.setAttribute("aria-hidden", "true");
  const label = document.createElement("span");
  label.textContent = message;
  state.append(spinner, label);
  target.append(state);
}

function addText(parent, tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  parent.append(element);
  return element;
}

function showError(target, error) {
  target.replaceChildren();
  addText(target, "h3", "", "Request could not be completed");
  addText(target, "div", "error-box", error.message);
}

function showHeader(target, kicker, title) {
  const header = document.createElement("div");
  header.className = "result-title";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const label = document.createElement("span");
  label.className = "result-kicker";
  label.textContent = kicker;
  header.append(heading, label);
  target.replaceChildren(header);
}

function showPrivacyNote(target, text) {
  addText(target, "p", "privacy-note", text);
}

function showMetrics(target, values) {
  const grid = document.createElement("div");
  grid.className = "metric-grid";
  values.forEach(([label, value]) => {
    const metric = document.createElement("div");
    metric.className = "metric";
    addText(metric, "span", "metric-label", label);
    addText(metric, "span", "metric-value", String(value));
    grid.append(metric);
  });
  target.append(grid);
}

async function postJson(path, payload) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json();
  if (!response.ok) {
    const detail = result.detail;
    throw new Error(Array.isArray(detail) ? detail.map((item) => item.msg).join("; ") : detail || "The API returned an error.");
  }
  return result;
}

function linesFrom(text) {
  return text.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
}

function integersFrom(text, label) {
  const values = text.split(",").map((part) => part.trim());
  if (!values.length || values.some((part) => !/^\d+$/.test(part))) {
    throw new Error(`${label} must be comma-separated, non-negative whole numbers.`);
  }
  return values.map(Number);
}

document.getElementById("registry-load-large").addEventListener("click", () => {
  document.getElementById("registry-records").value = Array.from(
    { length: 2048 },
    (_, index) => index % 4,
  ).join(",");
  document.getElementById("registry-index").value = "2047";
});

function bindForm(id, resultId, pendingMessage, handler) {
  const form = document.getElementById(id);
  const target = document.getElementById(resultId);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showLoading(target, pendingMessage);
    try {
      await handler(target);
    } catch (error) {
      showError(target, error);
    }
  });
}

const protocolGuides = {
  psi: {
    title: "What happens in DH-PSI?",
    useCase: "A bank checks customers against a regulator's sanctions list without sending either complete list to the other party.",
    steps: [
      ["Agree on identifiers", "Both sides normalize identifiers and hash them into the same prime-order group.", "BANK + REGULATOR"],
      ["Blind the bank's queries", "The bank raises each customer element to its secret exponent a and sends the blinded elements.", "BANK -> REGULATOR"],
      ["Re-blind the values", "The regulator raises the received values to secret b and returns them, alongside shuffled blinded watchlist elements.", "REGULATOR -> BANK"],
      ["Find only local matches", "The bank applies a to the shuffled watchlist elements and compares group elements. It learns which of its own customers matched.", "BANK"],
    ],
    takeaway: "The toy protocol still reveals list sizes and does not stop a malicious client from making repeated queries.",
  },
  aml: {
    title: "What happens in secure MPC?",
    useCase: "Banks combine private features to evaluate an AML rule, while the result reveals only whether the weighted risk meets a threshold.",
    steps: [
      ["Split each bank's features", "Each feature is split into two random additive shares. A single share does not reveal the original value.", "BANKS -> S0 + S1"],
      ["Compute on shares", "The servers use Beaver multiplication triples for weighted products, then add the shared products locally.", "S0 + S1"],
      ["Compare privately", "The score shares become inputs to a garbled comparison circuit that evaluates score >= threshold.", "GARBLER -> EVALUATOR"],
      ["Reveal the allowed output", "The relying party receives the one-bit threshold decision, not a cleartext score from this API.", "RESULT"],
    ],
    takeaway: "In this prototype the parties run inside one Python process, and the MPC pipeline reconstructs a score internally for checking; the web API deliberately returns only the flag.",
  },
  registry: {
    title: "What happens in a DORAM read?",
    useCase: "A bank or customer retrieves a KYC status from a shared registry without telling either storage server which index was requested.",
    steps: [
      ["Make a one-hot query", "The client represents its chosen index as a vector with one active position.", "CLIENT"],
      ["Randomly split the query", "The client sends two random additive shares whose sum is the one-hot vector, one to each server.", "CLIENT -> S0 + S1"],
      ["Servers compute locally", "Each server computes a dot product of its database with its own query share.", "S0 + S1"],
      ["Combine the answers", "The client adds the two replies and obtains the selected status without disclosing the index to either server.", "CLIENT"],
    ],
    takeaway: "This read-only teaching version has O(n) communication, stores a plaintext database at both servers, and assumes the servers do not collude.",
  },
  credential: {
    title: "What happens in a ZK credential check?",
    useCase: "A customer proves policy claims—such as adult age, an allowed nationality, and a sufficient KYC level—without giving the relying party their date of birth.",
    steps: [
      ["Issuer checks and signs", "The issuer verifies the demo attributes, signs their commitments, and checks knowledge of a wallet secret.", "ISSUER + WALLET"],
      ["Relying party requests claims", "The request includes the relying-party identity, a fresh nonce, and the policy to verify.", "RELYING PARTY"],
      ["Wallet creates one proof", "The wallet combines range, set-membership, signature, and holder-binding statements under a Fiat-Shamir challenge.", "WALLET"],
      ["Verifier checks the transcript", "The relying party verifies the issuer signature, requested predicates, context binding, and scoped nullifier.", "RELYING PARTY"],
    ],
    takeaway: "For this local demo the sample attributes are sent to the local Python API, which simulates the issuer and wallet. In a real design, attributes belong on the user's device.",
  },
  credbbs: {
    title: "What happens in a BBS+ showing?",
    useCase: "A customer gets a credential the issuer signs without seeing the wallet secret, then shows it to banks so that no two showings can be linked to the same person.",
    steps: [
      ["Seal the wallet secret", "The wallet commits to its secret key and proves it knows the opening; the issuer signs the commitment, never the raw secret.", "WALLET -> ISSUER"],
      ["Re-randomise each show", "Before presenting, the wallet multiplies the signature by fresh randomness, so every showing looks like different group elements.", "WALLET"],
      ["Prove without revealing", "A pairing check confirms the issuer signature and a zero-knowledge proof covers the hidden attributes; only the chosen attribute is disclosed.", "WALLET -> RELYING PARTY"],
      ["Scope the nullifier", "The per-relying-party nullifier is identical on repeat visits (so a second account is blocked) but unrelated across banks.", "RELYING PARTY"],
    ],
    takeaway: "This demo discloses nationality to satisfy the policy; proving a hidden threshold such as age >= 18 without revealing the value needs range proofs (Bulletproofs), left as future work.",
  },
};

function renderProtocolGuide(container, guide) {
  const state = { step: 0 };
  const content = document.createElement("div");
  content.className = "guide-content";
  const header = document.createElement("div");
  header.className = "guide-header";
  addText(header, "span", "guide-kicker", "PROTOCOL WALKTHROUGH");
  addText(header, "h2", "", guide.title);
  addText(header, "p", "guide-use-case", guide.useCase);

  const layout = document.createElement("div");
  layout.className = "guide-layout";
  const stepList = document.createElement("ol");
  stepList.className = "guide-step-list";
  const detail = document.createElement("div");
  detail.className = "guide-current";

  guide.steps.forEach(([title], index) => {
    const item = document.createElement("li");
    item.dataset.index = String(index);
    addText(item, "span", "guide-step-number", String(index + 1).padStart(2, "0"));
    addText(item, "span", "", title);
    stepList.append(item);
  });

  const renderStep = () => {
    const [title, description, actor] = guide.steps[state.step];
    [...stepList.children].forEach((item, index) => {
      item.classList.toggle("current", index === state.step);
      item.classList.toggle("complete", index < state.step);
    });
    detail.replaceChildren();
    addText(detail, "span", "guide-actor", actor);
    addText(detail, "h3", "", title);
    addText(detail, "p", "", description);
    const controls = document.createElement("div");
    controls.className = "guide-controls";
    const previous = addText(controls, "button", "button button-muted", "Previous");
    previous.type = "button";
    previous.disabled = state.step === 0;
    previous.addEventListener("click", () => {
      state.step -= 1;
      renderStep();
    });
    addText(controls, "span", "guide-count", `Step ${state.step + 1} of ${guide.steps.length}`);
    const next = addText(controls, "button", "button button-outline", state.step === guide.steps.length - 1 ? "Restart" : "Next step ->");
    next.type = "button";
    next.addEventListener("click", () => {
      state.step = state.step === guide.steps.length - 1 ? 0 : state.step + 1;
      renderStep();
    });
    detail.append(controls);
  };

  layout.append(stepList, detail);
  const note = document.createElement("div");
  note.className = "guide-takeaway";
  addText(note, "strong", "", "Prototype note");
  addText(note, "span", "", guide.takeaway);
  content.append(header, layout, note);
  container.replaceChildren(content);
  renderStep();
}

document.querySelectorAll("[data-guide]").forEach((container) => {
  renderProtocolGuide(container, protocolGuides[container.dataset.guide]);
});

bindForm("psi-form", "psi-result", "Running DH-PSI with the local protocol...", async (target) => {
  const data = await postJson("/api/psi", {
    watchlist: linesFrom(document.getElementById("psi-watchlist").value),
    customers: linesFrom(document.getElementById("psi-customers").value),
  });
  showHeader(target, "DH-PSI", "Screening result");
  if (data.matches.length) {
    const list = document.createElement("ul");
    list.className = "result-list";
    data.matches.forEach((match) => addText(list, "li", "", match));
    target.append(list);
  } else {
    addText(target, "p", "empty-match", "No customer entries matched the watchlist.");
  }
  showMetrics(target, [
    ["Bank customers", data.customer_count],
    ["Protocol messages", data.protocol_messages],
    ["Watchlist size", data.watchlist_size],
    ["Communication", `${data.communication_bytes.toLocaleString()} bytes`],
    ...(data.duplicate_customers_ignored
      ? [["Duplicate customer rows ignored", data.duplicate_customers_ignored]]
      : []),
    ...(data.duplicate_watchlist_entries_ignored
      ? [["Duplicate watchlist rows ignored", data.duplicate_watchlist_entries_ignored]]
      : []),
  ]);
  showPrivacyNote(target, data.duplicate_customers_ignored || data.duplicate_watchlist_entries_ignored
    ? `${data.privacy_note} Duplicate rows are treated as one identifier.`
    : data.privacy_note);
});

bindForm("aml-form", "aml-result", "Running the secure MPC demo; this may take a few seconds...", async (target) => {
  const weights = integersFrom(document.getElementById("aml-weights").value, "Weights");
  const banks = ["aml-bank-a", "aml-bank-b", "aml-bank-c"]
    .map((id) => document.getElementById(id).value.trim())
    .filter(Boolean)
    .map((values, index) => integersFrom(values, `Bank ${index + 1} features`));
  const threshold = Number(document.getElementById("aml-threshold").value);
  if (!Number.isInteger(threshold)) throw new Error("Threshold must be a whole number.");
  const data = await postJson("/api/aml", { banks, weights, threshold });
  showHeader(target, "HYBRID MPC", "Threshold decision");
  const verdict = document.createElement("div");
  verdict.className = `verdict ${data.flag ? "fail" : "pass"}`;
  addText(verdict, "span", "verdict-symbol", data.flag ? "!" : "OK");
  addText(verdict, "span", "", data.flag ? "Above threshold" : "Below threshold");
  target.append(verdict);
  addText(target, "p", "result-message", `The secure comparison evaluated the policy threshold of ${data.threshold.toLocaleString()}.`);
  showMetrics(target, [
    ["Protocol messages", data.protocol_messages],
    ["Communication", `${data.communication_bytes.toLocaleString()} bytes`],
  ]);
  showPrivacyNote(target, data.privacy_note);
});

bindForm("registry-form", "registry-result", "Splitting the query across both registry servers...", async (target) => {
  const records = integersFrom(document.getElementById("registry-records").value, "Registry statuses");
  const index = Number(document.getElementById("registry-index").value);
  if (!Number.isInteger(index)) throw new Error("Record index must be a whole number.");
  const data = await postJson("/api/registry", { records, index });
  showHeader(target, "2-SERVER DORAM", "Private registry read");
  const verdict = document.createElement("div");
  verdict.className = "verdict pass";
  addText(verdict, "span", "verdict-symbol", String(data.status_code));
  addText(verdict, "span", "", data.status_label);
  target.append(verdict);
  addText(target, "p", "result-message", `Read record ${index} from a ${data.registry_size}-entry demo registry.`);
  showMetrics(target, [
    ["Protocol messages", data.protocol_messages],
    ["Communication", `${data.communication_bytes.toLocaleString()} bytes`],
  ]);
  showPrivacyNote(target, data.privacy_note);
});

bindForm("credential-form", "credential-result", "Issuing the demo credential and generating a zero-knowledge proof...", async (target) => {
  const dob = document.getElementById("credential-dob").value;
  const parts = dob.split("-").map(Number);
  if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part))) {
    throw new Error("Enter a valid date of birth.");
  }
  const [year, month, day] = parts;
  const data = await postJson("/api/credential", {
    dob: year * 10000 + month * 100 + day,
    nationality: Number(document.getElementById("credential-nationality").value),
    kyc_level: Number(document.getElementById("credential-level").value),
    relying_party: document.getElementById("credential-rp").value.trim(),
  });
  showHeader(target, "ZERO-KNOWLEDGE PROOF", "Credential verification");
  const verdict = document.createElement("div");
  verdict.className = `verdict ${data.accepted ? "pass" : "fail"}`;
  addText(verdict, "span", "verdict-symbol", data.accepted ? "OK" : "!");
  addText(verdict, "span", "", data.accepted ? "Policy accepted" : "Policy not satisfied");
  target.append(verdict);
  if (data.reason) addText(target, "p", "result-message", data.reason);
  if (data.proof_generated) addText(target, "p", "result-message", `Proof verified for ${data.relying_party}.`);
  showPrivacyNote(target, data.privacy_note);
});

bindForm("credbbs-form", "credbbs-result", "Blindly issuing and presenting the BBS+ credential; pairings take a few seconds...", async (target) => {
  const dob = document.getElementById("credbbs-dob").value;
  const parts = dob.split("-").map(Number);
  if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part))) {
    throw new Error("Enter a valid date of birth.");
  }
  const [year, month, day] = parts;
  const data = await postJson("/api/credential-bbs", {
    dob: year * 10000 + month * 100 + day,
    nationality: Number(document.getElementById("credbbs-nationality").value),
    kyc_level: Number(document.getElementById("credbbs-level").value),
    relying_party: document.getElementById("credbbs-rp").value.trim(),
  });
  showHeader(target, "BBS+ CREDENTIAL", "Unlinkable presentation");
  const verdict = document.createElement("div");
  verdict.className = `verdict ${data.accepted ? "pass" : "fail"}`;
  addText(verdict, "span", "verdict-symbol", data.accepted ? "OK" : "!");
  addText(verdict, "span", "", data.accepted ? `Accepted at ${data.relying_party}` : "Policy not satisfied");
  target.append(verdict);
  addText(target, "p", "result-message", data.issuer_saw_sk
    ? "The issuer saw the wallet secret."
    : "Blind issuance: the issuer signed the credential without ever seeing the wallet secret (sk).");
  showMetrics(target, [
    ["Show #1 fingerprint", data.show1_fingerprint],
    ["Show #2 fingerprint", data.show2_fingerprint],
    ["Two shows unlinkable", data.shows_unlinkable ? "yes" : "no"],
    [`Nullifier at ${data.relying_party}`, data.nullifier_here],
    [`Nullifier at ${data.other_relying_party}`, data.nullifier_other],
    ["Different banks unlinkable", data.cross_rp_unlinkable ? "yes" : "no"],
    ["2nd account at same bank", data.second_show_accepted ? "accepted" : "blocked"],
    ["Sybil blocked", data.sybil_blocked ? "yes" : "no"],
  ]);
  showPrivacyNote(target, data.privacy_note);
  addText(target, "p", "privacy-note", data.scope_note);
});

const attackSelect = document.getElementById("attack-select");
const attackOverview = document.getElementById("attack-overview");
const attackWalkthrough = document.getElementById("attack-walkthrough");
const attackInputFields = document.getElementById("attack-input-fields");
const attackResult = document.getElementById("attack-result");
const attackRunButtons = ["attack-run-v0", "attack-run-v1", "attack-run-both"]
  .map((id) => document.getElementById(id));
let attackCatalog = [];
let selectedAttack = null;
let attackStepIndex = 0;
let latestAttackResults = {};

function addGuideText(parent, tag, className, text) {
  return addText(parent, tag, className, text);
}

function renderAttackWalkthrough() {
  if (!selectedAttack) {
    attackWalkthrough.replaceChildren();
    return;
  }
  const step = selectedAttack.steps[attackStepIndex];
  attackWalkthrough.replaceChildren();
  addGuideText(attackWalkthrough, "span", "guide-kicker", "ATTACK WALKTHROUGH");
  const progress = document.createElement("div");
  progress.className = "attack-progress";
  selectedAttack.steps.forEach((_, index) => {
    const marker = document.createElement("span");
    marker.className = index === attackStepIndex ? "current" : index < attackStepIndex ? "complete" : "";
    progress.append(marker);
  });
  attackWalkthrough.append(progress);
  addGuideText(attackWalkthrough, "span", "guide-actor", `STEP ${attackStepIndex + 1} / ${selectedAttack.steps.length}`);
  addGuideText(attackWalkthrough, "h3", "", step);
  const controls = document.createElement("div");
  controls.className = "guide-controls";
  const previous = addGuideText(controls, "button", "button button-muted", "Previous");
  previous.type = "button";
  previous.disabled = attackStepIndex === 0;
  previous.addEventListener("click", () => {
    attackStepIndex -= 1;
    renderAttackWalkthrough();
  });
  const next = addGuideText(controls, "button", "button button-outline", attackStepIndex === selectedAttack.steps.length - 1 ? "Restart" : "Next step ->");
  next.type = "button";
  next.addEventListener("click", () => {
    attackStepIndex = attackStepIndex === selectedAttack.steps.length - 1 ? 0 : attackStepIndex + 1;
    renderAttackWalkthrough();
  });
  attackWalkthrough.append(controls);
}

function renderAttackInputs(attack) {
  attackInputFields.replaceChildren();
  if (!attack.inputs.length) {
    addGuideText(attackInputFields, "p", "attack-no-input", "This scenario uses its bundled fictional demonstration data. You can still choose which system to test.");
    return;
  }
  addGuideText(attackInputFields, "h3", "", "Change the attacker input");
  attack.inputs.forEach((field) => {
    const label = document.createElement("label");
    label.htmlFor = `attack-input-${field.name}`;
    label.textContent = field.label;
    const input = document.createElement(field.type === "textarea" ? "textarea" : "input");
    input.id = `attack-input-${field.name}`;
    input.dataset.attackInput = field.name;
    if (field.type === "textarea") {
      input.rows = 3;
      input.value = field.default;
    } else {
      input.type = field.type;
      input.min = field.name === "amount" ? "0" : "1";
      input.max = field.name === "attempts" ? "25" : field.name === "range_start" ? "999999" : field.name === "range_count" ? "10000" : "10000";
      input.value = String(field.default);
    }
    input.required = true;
    addGuideText(attackInputFields, "p", "attack-input-help", field.help);
    attackInputFields.append(label, input);
  });
}

function renderSelectedAttack() {
  const attack = selectedAttack;
  latestAttackResults = {};
  if (!attack) {
    attackOverview.replaceChildren();
    attackWalkthrough.replaceChildren();
    attackInputFields.replaceChildren();
    attackRunButtons.forEach((button) => { button.disabled = true; });
    return;
  }
  attackRunButtons.forEach((button) => { button.disabled = false; });
  attackOverview.replaceChildren();
  addGuideText(attackOverview, "span", "guide-actor", `ATTACK #${attack.number} / USE CASE`);
  addGuideText(attackOverview, "p", "attack-use-case", attack.use_case);
  addGuideText(attackOverview, "p", "attack-description", attack.what_happens);
  const comparison = document.createElement("div");
  comparison.className = "attack-expectations";
  addGuideText(comparison, "div", "attack-expectation-v0", `v0 · ${attack.v0}`);
  addGuideText(comparison, "div", "attack-expectation-v1", `v1 · ${attack.v1}`);
  attackOverview.append(comparison);
  const defence = document.createElement("div");
  defence.className = "attack-defense";
  addGuideText(defence, "strong", "", "Course concept");
  addGuideText(defence, "span", "", attack.defence);
  attackOverview.append(defence);
  attackStepIndex = 0;
  renderAttackWalkthrough();
  renderAttackInputs(attack);
  showAttackOutcomes();
}

function readAttackInputs() {
  const params = {};
  selectedAttack.inputs.forEach((field) => {
    const input = document.getElementById(`attack-input-${field.name}`);
    if (field.name === "candidate_ids") {
      params.candidate_ids = linesFrom(input.value);
      if (!params.candidate_ids.length) throw new Error("Enter at least one candidate ID.");
      return;
    }
    const value = Number(input.value);
    if (!Number.isInteger(value)) throw new Error(`${field.label} must be a whole number.`);
    params[field.name] = value;
  });
  return params;
}

function showAttackOutcomes(loadingSystem = null) {
  const results = Object.values(latestAttackResults);
  if (!results.length && !loadingSystem) {
    attackResult.innerHTML = '<div class="result-placeholder"><span class="placeholder-icon">!</span><h3>Choose how to run this scenario</h3><p>Run it against v0, v1, or compare the same attack against both systems.</p></div>';
    return;
  }
  attackResult.replaceChildren();
  const header = document.createElement("div");
  header.className = "result-title";
  addGuideText(header, "h3", "", loadingSystem ? `Running on ${loadingSystem}...` : "What the run showed");
  addGuideText(header, "span", "result-kicker", selectedAttack.name);
  attackResult.append(header);
  if (loadingSystem) {
    const loading = document.createElement("div");
    loading.className = "loading";
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    loading.append(spinner);
    addGuideText(loading, "span", "", "Executing the selected attack scenario...");
    attackResult.append(loading);
  }
  const comparison = document.createElement("div");
  comparison.className = "attack-outcome-grid";
  ["v0", "v1"].forEach((system) => {
    const data = latestAttackResults[system];
    const card = document.createElement("article");
    card.className = `attack-outcome ${system}`;
    addGuideText(card, "span", "guide-actor", system === "v0" ? "INTENTIONALLY VULNERABLE" : "PROTECTED PROTOTYPE");
    addGuideText(card, "h3", "", system);
    if (data) {
      const tone = data.attack_succeeded ? (system === "v0" ? "danger" : "warning") : "safe";
      addGuideText(card, "div", `attack-status ${tone}`, data.attack_succeeded
        ? system === "v0" ? "Attack succeeded" : "Residual risk"
        : system === "v0" ? "Attempt did not succeed" : "Attack blocked");
      addGuideText(card, "p", "attack-interpretation", data.interpretation);
      addGuideText(card, "p", "attack-metric", `Observed: ${data.metric}`);
      addGuideText(card, "p", "attack-evidence", data.evidence);
    } else {
      addGuideText(card, "p", "attack-not-run", "Not run yet. Use the buttons to test this side.");
    }
    comparison.append(card);
  });
  attackResult.append(comparison);
  const caveat = document.createElement("p");
  caveat.className = "privacy-note";
  caveat.textContent = "A successful v0 run demonstrates the weakness in the deliberately vulnerable baseline. A v1 residual-risk result means the mitigation is incomplete—not that the test passed.";
  attackResult.append(caveat);
}

async function executeAttack(system) {
  if (!selectedAttack) return;
  const params = readAttackInputs();
  attackRunButtons.forEach((button) => { button.disabled = true; });
  showAttackOutcomes(system);
  try {
    latestAttackResults[system] = await postJson(`/api/attacks/${selectedAttack.number}`, { system, ...params });
  } catch (error) {
    showError(attackResult, error);
    return;
  } finally {
    attackRunButtons.forEach((button) => { button.disabled = false; });
  }
  showAttackOutcomes();
}

attackSelect.addEventListener("change", () => {
  selectedAttack = attackCatalog.find((attack) => attack.number === Number(attackSelect.value)) || null;
  renderSelectedAttack();
});

document.getElementById("attack-run-v0").addEventListener("click", () => executeAttack("v0"));
document.getElementById("attack-run-v1").addEventListener("click", () => executeAttack("v1"));
document.getElementById("attack-run-both").addEventListener("click", async () => {
  if (!selectedAttack) return;
  let params;
  try {
    params = readAttackInputs();
  } catch (error) {
    showError(attackResult, error);
    return;
  }
  attackRunButtons.forEach((button) => { button.disabled = true; });
  latestAttackResults = {};
  showAttackOutcomes("v0 and v1");
  try {
    latestAttackResults.v0 = await postJson(`/api/attacks/${selectedAttack.number}`, { system: "v0", ...params });
    showAttackOutcomes("v1");
    latestAttackResults.v1 = await postJson(`/api/attacks/${selectedAttack.number}`, { system: "v1", ...params });
    showAttackOutcomes();
  } catch (error) {
    showError(attackResult, error);
  } finally {
    attackRunButtons.forEach((button) => { button.disabled = false; });
  }
});

async function loadAttackCatalog() {
  try {
    const response = await fetch(`${API_BASE}/api/attacks/catalog`);
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Could not load attack scenarios.");
    attackCatalog = result.attacks;
    attackSelect.replaceChildren();
    attackCatalog.forEach((attack) => {
      const option = document.createElement("option");
      option.value = String(attack.number);
      option.textContent = `${String(attack.number).padStart(2, "0")} · ${attack.name}`;
      attackSelect.append(option);
    });
    selectedAttack = attackCatalog[0] || null;
    renderSelectedAttack();
  } catch (error) {
    attackSelect.replaceChildren();
    const option = document.createElement("option");
    option.textContent = "Attack catalog unavailable";
    attackSelect.append(option);
    showError(attackOverview, error);
  }
}

async function checkApi() {
  const dot = document.getElementById("api-dot");
  const status = document.getElementById("api-status");
  try {
    const response = await fetch(`${API_BASE}/api/health`);
    if (!response.ok) throw new Error("API unavailable");
    dot.classList.add("online");
    status.textContent = "API connected";
  } catch {
    dot.classList.remove("online");
    status.textContent = "API not running";
  }
}

checkApi();
loadAttackCatalog();
