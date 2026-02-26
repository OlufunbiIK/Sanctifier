# Contributor Guide: Static Analysis Rules & Formal Verification Templates

> **Audience:** Researchers and engineers who want to extend the project's verification capabilities by adding new static analysis rules or formal verification templates.

---

## Table of Contents

1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [Contributing Static Analysis Rules](#contributing-static-analysis-rules)
4. [Contributing Formal Verification Templates](#contributing-formal-verification-templates)
5. [Testing Your Contributions](#testing-your-contributions)
6. [Submitting a Pull Request](#submitting-a-pull-request)
7. [Style & Naming Conventions](#style--naming-conventions)
8. [Getting Help](#getting-help)

---

## Overview

This project supports two complementary verification mechanisms:

| Mechanism                         | Purpose                                                                          | Best For                                                        |
| --------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Static Analysis Rules**         | Detect code patterns, anti-patterns, or policy violations without executing code | Linting, security scanning, style enforcement                   |
| **Formal Verification Templates** | Prove correctness properties using mathematical reasoning                        | Safety-critical invariants, protocol correctness, memory safety |

Both are first-class contributions. This guide walks you through the end-to-end process for each.

---

## Repository Structure

```
/
├── rules/
│   ├── static/               # Static analysis rule definitions
│   │   ├── security/         # Security-focused rules
│   │   ├── correctness/      # Logic and correctness rules
│   │   └── style/            # Code style rules
│   └── schemas/
│       └── rule_schema.json  # JSON schema for rule validation
│
├── verification/
│   ├── templates/            # Formal verification templates
│   │   ├── invariants/       # Loop and data structure invariants
│   │   ├── contracts/        # Pre/postcondition contracts
│   │   └── protocols/        # Communication/concurrency protocols
│   └── schemas/
│       └── template_schema.json
│
├── tests/
│   ├── static/               # Test cases for static rules
│   └── verification/         # Test cases for verification templates
│
└── docs/
    └── examples/             # Annotated worked examples
```

---

## Contributing Static Analysis Rules

### Step 1 — Understand the Rule Format

Each rule is defined in a single `.yaml` file. Below is the minimal required structure:

```yaml
# rules/static/correctness/no-unchecked-null.yaml

id: SA-CORRECT-001
name: no-unchecked-null-dereference
version: "1.0.0"
severity: error # error | warning | info
category: correctness # security | correctness | style | performance

description: >
  Flags pointer dereferences that are not preceded by a null check
  within the same scope.

rationale: >
  Dereferencing a null pointer causes undefined behavior. All
  externally sourced pointers must be validated before use.

# Pattern matching specification
pattern:
  language: c # c | cpp | python | java | rust | ...
  engine: semgrep # semgrep | codeql | custom
  match: |
    $PTR = $SOURCE(...)
    *$PTR

# One or more test cases (required — see Testing section)
examples:
  - id: ex-1
    label: "Triggers rule"
    should_match: true
    code: |
      char *buf = get_input();
      printf("%s", *buf);

  - id: ex-2
    label: "Does not trigger after null check"
    should_match: false
    code: |
      char *buf = get_input();
      if (buf != NULL) {
          printf("%s", *buf);
      }

references:
  - "CWE-476: NULL Pointer Dereference"
  - "https://example.com/related-work"

authors:
  - name: "Jane Researcher"
    affiliation: "Example University"
    contact: "jane@example.edu"
```

### Step 2 — Choose the Right Category and Severity

**Categories**

- `security` — Rules that detect vulnerabilities (injection, memory corruption, auth bypass, etc.)
- `correctness` — Rules that detect logic errors or undefined behavior
- `style` — Rules that enforce project coding conventions
- `performance` — Rules that flag known performance anti-patterns

**Severity Levels**

| Severity  | Meaning                         | CI Behavior  |
| --------- | ------------------------------- | ------------ |
| `error`   | Must be fixed; blocks merge     | CI fails     |
| `warning` | Should be fixed; does not block | CI warns     |
| `info`    | Informational only              | No CI impact |

### Step 3 — Write the Pattern

The project supports multiple pattern engines. Choose based on what you need:

- **Semgrep** — Great for syntactic patterns across many languages. Use for most new rules.
- **CodeQL** — Use when data-flow or control-flow analysis is needed.
- **Custom** — Only if neither above is sufficient; requires a Python plugin in `rules/engines/custom/`.

See `docs/examples/semgrep-patterns.md` and `docs/examples/codeql-patterns.md` for annotated pattern examples.

### Step 4 — Assign a Rule ID

IDs follow this format:

```
SA-{CATEGORY_PREFIX}-{NUMBER}
```

| Category    | Prefix  |
| ----------- | ------- |
| security    | SEC     |
| correctness | CORRECT |
| style       | STYLE   |
| performance | PERF    |

To claim the next available number, run:

```bash
make next-rule-id CATEGORY=correctness
# Output: SA-CORRECT-042
```

---

## Contributing Formal Verification Templates

### Step 1 — Understand the Template Format

Verification templates are parameterized proof skeletons. A template describes _what_ to prove; a user fills in parameters to instantiate it for a specific function or module.

```yaml
# verification/templates/contracts/bounded-buffer-insert.yaml

id: VT-CONTRACT-007
name: bounded-buffer-insert-contract
version: "1.0.0"
prover: frama-c # frama-c | dafny | coq | isabelle | tla-plus

description: >
  Pre/postcondition contract for inserting into a bounded buffer.
  Proves that capacity is never exceeded and the element is
  correctly written.

# Parameters that the user must supply
parameters:
  - name: BUFFER_TYPE
    type: c_type
    description: "C type of the buffer struct"
  - name: MAX_CAPACITY
    type: integer
    description: "Maximum number of elements"
  - name: INSERT_FN
    type: function_name
    description: "Name of the insert function to verify"

# The template body (parameterized)
template: |
  /*@ requires \valid(buf) && buf->size < {{MAX_CAPACITY}};
    @ assigns buf->data[buf->size], buf->size;
    @ ensures buf->size == \old(buf->size) + 1;
    @ ensures buf->data[\old(buf->size)] == elem;
    @*/
  void {{INSERT_FN}}({{BUFFER_TYPE}} *buf, int elem);

# A worked instantiation for documentation/testing
example_instantiation:
  parameters:
    BUFFER_TYPE: RingBuffer
    MAX_CAPACITY: 64
    INSERT_FN: ring_buffer_push
  expected_result: verified # verified | counterexample | unknown

proof_obligations:
  - "buf->size remains strictly less than MAX_CAPACITY after insert"
  - "No other memory locations are modified"
  - "Element appears at the expected index"

references:
  - "Frama-C ACSL Manual §4.3"
  - "https://doi.org/10.xxxx/related-paper"

authors:
  - name: "Priya Verifier"
    affiliation: "Formal Methods Lab"
```

### Step 2 — Choose a Prover

| Prover           | Strengths                                       | File Extension            |
| ---------------- | ----------------------------------------------- | ------------------------- |
| **Frama-C / WP** | C code, ACSL annotations                        | `.c` + `.yaml` template   |
| **Dafny**        | Imperative programs with built-in spec language | `.dfy` + `.yaml` template |
| **Coq**          | Full theorem proving, math-heavy properties     | `.v` + `.yaml` template   |
| **Isabelle/HOL** | Large-scale proofs, higher-order logic          | `.thy` + `.yaml` template |
| **TLA+**         | Concurrent systems, protocol verification       | `.tla` + `.yaml` template |

When in doubt, prefer **Dafny** for new algorithmic templates (good tooling, readable specs) and **TLA+** for concurrency/protocol templates.

### Step 3 — Assign a Template ID

```
VT-{TYPE_PREFIX}-{NUMBER}
```

| Type       | Prefix   |
| ---------- | -------- |
| invariants | INV      |
| contracts  | CONTRACT |
| protocols  | PROTO    |

```bash
make next-template-id TYPE=contracts
# Output: VT-CONTRACT-031
```

### Step 4 — Document Proof Obligations

Every template must list its proof obligations explicitly in plain English under `proof_obligations`. This helps reviewers understand what is being verified without reading the formal spec.

---

## Testing Your Contributions

All contributions **must** pass automated tests before review.

### Static Analysis Rules

Place test fixtures in `tests/static/{rule-id}/`:

```
tests/static/SA-CORRECT-001/
├── should_match/
│   ├── ex1.c
│   └── ex2.c
└── should_not_match/
    ├── ex3.c
    └── ex4.c
```

Run rule tests:

```bash
make test-rule RULE=SA-CORRECT-001
```

All files in `should_match/` must trigger the rule; all files in `should_not_match/` must not.

### Formal Verification Templates

Place instantiation test cases in `tests/verification/{template-id}/`:

```
tests/verification/VT-CONTRACT-007/
├── verified/        # Cases that should verify successfully
│   └── ring_buffer.c
└── counterexample/  # Cases that should produce a counterexample
    └── ring_buffer_broken.c
```

Run template tests:

```bash
make test-template TEMPLATE=VT-CONTRACT-007
```

### Running All Tests Locally

```bash
make test              # Run all tests
make test-static       # Run only static analysis tests
make test-verification # Run only verification tests
make lint-rules        # Validate YAML against schemas
```

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch named `rule/SA-CORRECT-001` or `template/VT-CONTRACT-007`.

2. **Commit** your rule/template YAML and all test fixtures together in one logical commit.

3. **Update** `CHANGELOG.md` under the `[Unreleased]` section with a one-line description.

4. **Open a PR** using the provided template. The PR description should include:
   - Motivation: what problem does this rule/template address?
   - False positive rate: estimated or measured on a real codebase
   - References to prior work or CVEs if applicable

5. **CI must pass** — the GitHub Actions workflow runs schema validation, rule tests, and verification tests automatically.

6. A maintainer will review within **5 business days**. Expect feedback on pattern precision, test coverage, and documentation clarity.

---

## Style & Naming Conventions

- Rule and template YAML keys use `kebab-case`.
- Pattern code blocks preserve original language indentation.
- All `description` and `rationale` fields must be written in full sentences.
- Do not embed prose in `template` blocks — keep them spec-only.
- IDs are immutable once merged. If a rule is deprecated, set `status: deprecated` and add a `superseded_by` field; do not delete or renumber.

---

## Getting Help

| Channel                                    | Use For                                |
| ------------------------------------------ | -------------------------------------- |
| GitHub Discussions → _Rules & Templates_   | Design questions before writing a rule |
| GitHub Issues                              | Bug reports against existing rules     |
| `#verification` (project Slack/Discord)    | Real-time help with prover tooling     |
| Weekly office hours (see project calendar) | In-depth review of complex templates   |

Before opening an issue, search existing rules and templates — the pattern you need may already exist or be in progress.

---

_Last updated: February 2026. For corrections or additions, open a PR against `docs/CONTRIBUTING_ANALYSIS_RULES.md`._
