# Decentralized Pause Mechanism — Reference Pattern

> **Purpose:** A production-ready, auditable reference for implementing an emergency pause mechanism in smart contracts without relying on a single privileged admin key.

---

## Table of Contents

1. [Design Goals](#design-goals)
2. [Architecture Overview](#architecture-overview)
3. [Role Model](#role-model)
4. [Core Solidity Implementation](#core-solidity-implementation)
   - [PauseGuard.sol — Base Contract](#pauseguardsol--base-contract)
   - [PauseCouncil.sol — Multisig Voting](#pausecouncilsol--multisig-voting)
   - [ExampleProtocol.sol — Integration](#exampleprotocolsol--integration)
5. [Formal Invariants](#formal-invariants)
6. [State Machine](#state-machine)
7. [Attack Surface & Mitigations](#attack-surface--mitigations)
8. [Testing Checklist](#testing-checklist)
9. [Deployment Checklist](#deployment-checklist)
10. [Variant Patterns](#variant-patterns)
11. [References](#references)

---

## Design Goals

| Goal                              | Approach                                                                                  |
| --------------------------------- | ----------------------------------------------------------------------------------------- |
| No single point of failure        | M-of-N guardian multisig; no single key can pause                                         |
| Censorship resistance             | Any guardian can _propose_; threshold required to _execute_                               |
| Automatic expiry                  | Pauses auto-expire after a configurable TTL                                               |
| Unpause requires higher consensus | Unpausing requires a larger quorum than pausing                                           |
| On-chain transparency             | All votes and state changes emit auditable events                                         |
| Upgrade-safe                      | Pause state lives in a separate contract; protocol logic is unaware of governance details |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        PauseCouncil                          │
│                                                               │
│  Guardians: [G1, G2, G3, G4, G5]   (M-of-N multisig)       │
│                                                               │
│  PAUSE  threshold:  ceil(N/3)  ← low bar for fast response  │
│  UNPAUSE threshold: ceil(2N/3) ← high bar to resume safely   │
│                                                               │
│  Emits: PauseProposed, PauseExecuted, UnpauseExecuted        │
└────────────────────┬────────────────────────────────────────┘
                     │ calls
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                        PauseGuard                             │
│                                                               │
│  paused: bool                                                 │
│  pauseExpiry: uint256  (auto-expire timestamp)               │
│  authorizedCaller: address  (only PauseCouncil)              │
│                                                               │
│  modifier: whenNotPaused()                                    │
└────────────────────┬────────────────────────────────────────┘
                     │ inherited by
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    ExampleProtocol                            │
│                                                               │
│  deposit()   → whenNotPaused                                 │
│  withdraw()  → whenNotPaused                                 │
│  liquidate() → always allowed  (emergency exit)              │
└─────────────────────────────────────────────────────────────┘
```

**Key design decision:** The protocol contract never imports governance logic. It depends only on `PauseGuard`, which exposes a simple `paused()` view. This separation allows the council composition to be upgraded without touching the protocol.

---

## Role Model

| Role             | Who Holds It                                                                          | Capabilities                            |
| ---------------- | ------------------------------------------------------------------------------------- | --------------------------------------- |
| **Guardian**     | Elected multisig members (e.g., security researchers, core team, community delegates) | Propose pause, vote to pause/unpause    |
| **PauseCouncil** | The multisig contract itself                                                          | Execute pause / unpause on `PauseGuard` |
| **PauseGuard**   | Deployed singleton                                                                    | Maintain canonical pause state          |
| **Protocol**     | Application contracts                                                                 | Read pause state; cannot modify it      |

No EOA (externally owned account) can pause unilaterally. The minimum attack surface for griefing is `ceil(N/3)` compromised guardian keys.

---

## Core Solidity Implementation

### PauseGuard.sol — Base Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PauseGuard
 * @notice Canonical pause state keeper. Only the authorized PauseCouncil
 *         can flip the paused flag. Pauses automatically expire after TTL.
 *
 * @dev Deploy this contract first, then pass its address to PauseCouncil.
 *      Protocol contracts inherit (or reference) this contract for the
 *      whenNotPaused modifier.
 */
contract PauseGuard {
    // ── State ──────────────────────────────────────────────────────────────

    /// @notice Address of the PauseCouncil contract. Immutable after init.
    address public immutable council;

    /// @notice Whether the protocol is currently paused.
    bool private _paused;

    /// @notice Unix timestamp at which the pause automatically expires.
    ///         Zero means no active pause.
    uint256 public pauseExpiry;

    /// @notice Maximum pause duration (7 days). Prevents indefinite lockout.
    uint256 public constant MAX_PAUSE_DURATION = 7 days;

    // ── Events ─────────────────────────────────────────────────────────────

    event Paused(address indexed by, uint256 expiry);
    event Unpaused(address indexed by);
    event PauseExpired();

    // ── Errors ─────────────────────────────────────────────────────────────

    error NotCouncil();
    error AlreadyPaused();
    error NotPaused();
    error DurationExceedsMax(uint256 requested, uint256 max);

    // ── Constructor ────────────────────────────────────────────────────────

    constructor(address _council) {
        require(_council != address(0), "PauseGuard: zero council");
        council = _council;
    }

    // ── Modifiers ──────────────────────────────────────────────────────────

    modifier onlyCouncil() {
        if (msg.sender != council) revert NotCouncil();
        _;
    }

    /**
     * @notice Reverts if the contract is paused and the pause has not expired.
     *         If the pause has expired, silently clears the paused state.
     */
    modifier whenNotPaused() {
        _checkNotPaused();
        _;
    }

    // ── External (Council-only) ─────────────────────────────────────────────

    /**
     * @notice Activate the emergency pause.
     * @param duration Seconds until automatic expiry. Must be ≤ MAX_PAUSE_DURATION.
     */
    function pause(uint256 duration) external onlyCouncil {
        if (_paused && block.timestamp < pauseExpiry) revert AlreadyPaused();
        if (duration > MAX_PAUSE_DURATION)
            revert DurationExceedsMax(duration, MAX_PAUSE_DURATION);

        _paused = true;
        pauseExpiry = block.timestamp + duration;

        emit Paused(msg.sender, pauseExpiry);
    }

    /**
     * @notice Lift the emergency pause before it expires.
     */
    function unpause() external onlyCouncil {
        if (!_paused || block.timestamp >= pauseExpiry) revert NotPaused();

        _paused = false;
        pauseExpiry = 0;

        emit Unpaused(msg.sender);
    }

    // ── Public View ────────────────────────────────────────────────────────

    /**
     * @notice Returns true if the protocol is actively paused.
     *         Accounts for automatic TTL expiry.
     */
    function paused() public view returns (bool) {
        if (!_paused) return false;
        if (block.timestamp >= pauseExpiry) return false; // expired
        return true;
    }

    // ── Internal ───────────────────────────────────────────────────────────

    function _checkNotPaused() internal {
        if (_paused) {
            if (block.timestamp >= pauseExpiry) {
                // Lazily clear expired pause (state write on first post-expiry call)
                _paused = false;
                pauseExpiry = 0;
                emit PauseExpired();
            } else {
                revert("PauseGuard: paused");
            }
        }
    }
}
```

---

### PauseCouncil.sol — Multisig Voting

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PauseGuard.sol";

/**
 * @title PauseCouncil
 * @notice M-of-N guardian multisig that controls PauseGuard.
 *
 *   - PAUSE  requires PAUSE_THRESHOLD  votes  (ceil(N/3)  — fast response)
 *   - UNPAUSE requires UNPAUSE_THRESHOLD votes  (ceil(2N/3) — conservative)
 *
 * Proposals expire after PROPOSAL_TTL to prevent stale votes being executed.
 *
 * @dev Guardians are set at construction and cannot be changed. To rotate
 *      guardians, deploy a new PauseCouncil and call PauseGuard.transferCouncil()
 *      (if the upgrade path is enabled — see Variant Patterns).
 */
contract PauseCouncil {
    // ── Types ──────────────────────────────────────────────────────────────

    enum ProposalKind { Pause, Unpause }

    struct Proposal {
        ProposalKind kind;
        uint256 duration;       // Only used for Pause proposals
        uint256 createdAt;
        uint256 voteCount;
        bool executed;
        mapping(address => bool) voted;
    }

    // ── Constants ──────────────────────────────────────────────────────────

    /// @notice Proposals expire if not executed within this window.
    uint256 public constant PROPOSAL_TTL = 1 hours;

    // ── State ──────────────────────────────────────────────────────────────

    PauseGuard public immutable guard;

    address[] public guardians;
    mapping(address => bool) public isGuardian;

    uint256 public immutable pauseThreshold;    // ceil(N/3)
    uint256 public immutable unpauseThreshold;  // ceil(2N/3)

    uint256 private _nextProposalId;
    mapping(uint256 => Proposal) private _proposals;

    // ── Events ─────────────────────────────────────────────────────────────

    event ProposalCreated(uint256 indexed id, ProposalKind kind, address indexed proposer);
    event Voted(uint256 indexed id, address indexed guardian);
    event ProposalExecuted(uint256 indexed id, ProposalKind kind);
    event ProposalExpired(uint256 indexed id);

    // ── Errors ─────────────────────────────────────────────────────────────

    error NotGuardian();
    error AlreadyVoted();
    error ProposalNotFound();
    error ProposalAlreadyExecuted();
    error ProposalExpiredError();
    error ThresholdNotMet(uint256 have, uint256 need);

    // ── Constructor ────────────────────────────────────────────────────────

    /**
     * @param _guard       Address of the deployed PauseGuard.
     * @param _guardians   Initial guardian set (no duplicates, no zero addresses).
     */
    constructor(address _guard, address[] memory _guardians) {
        require(_guard != address(0), "PauseCouncil: zero guard");
        require(_guardians.length >= 3, "PauseCouncil: need at least 3 guardians");

        guard = PauseGuard(_guard);

        for (uint256 i = 0; i < _guardians.length; i++) {
            address g = _guardians[i];
            require(g != address(0), "PauseCouncil: zero guardian");
            require(!isGuardian[g], "PauseCouncil: duplicate guardian");
            guardians.push(g);
            isGuardian[g] = true;
        }

        uint256 n = _guardians.length;
        pauseThreshold   = (n + 2) / 3;        // ceil(N/3)
        unpauseThreshold = (2 * n + 2) / 3;    // ceil(2N/3)
    }

    // ── Modifiers ──────────────────────────────────────────────────────────

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert NotGuardian();
        _;
    }

    // ── External ───────────────────────────────────────────────────────────

    /**
     * @notice Propose and immediately cast the first vote to pause.
     * @param duration Pause duration in seconds (forwarded to PauseGuard).
     * @return id The new proposal ID.
     */
    function proposePause(uint256 duration)
        external
        onlyGuardian
        returns (uint256 id)
    {
        id = _createProposal(ProposalKind.Pause, duration);
        _vote(id); // proposer auto-votes
    }

    /**
     * @notice Propose and immediately cast the first vote to unpause.
     * @return id The new proposal ID.
     */
    function proposeUnpause()
        external
        onlyGuardian
        returns (uint256 id)
    {
        id = _createProposal(ProposalKind.Unpause, 0);
        _vote(id);
    }

    /**
     * @notice Cast a vote on an existing proposal.
     *         Automatically executes once the threshold is reached.
     */
    function vote(uint256 id) external onlyGuardian {
        _vote(id);
    }

    // ── Public View ────────────────────────────────────────────────────────

    function getProposal(uint256 id)
        external
        view
        returns (
            ProposalKind kind,
            uint256 duration,
            uint256 createdAt,
            uint256 voteCount,
            bool executed,
            bool expired
        )
    {
        Proposal storage p = _proposals[id];
        require(p.createdAt != 0, "PauseCouncil: unknown proposal");
        return (
            p.kind,
            p.duration,
            p.createdAt,
            p.voteCount,
            p.executed,
            block.timestamp > p.createdAt + PROPOSAL_TTL
        );
    }

    function guardianCount() external view returns (uint256) {
        return guardians.length;
    }

    // ── Internal ───────────────────────────────────────────────────────────

    function _createProposal(ProposalKind kind, uint256 duration)
        internal
        returns (uint256 id)
    {
        id = _nextProposalId++;
        Proposal storage p = _proposals[id];
        p.kind      = kind;
        p.duration  = duration;
        p.createdAt = block.timestamp;

        emit ProposalCreated(id, kind, msg.sender);
    }

    function _vote(uint256 id) internal {
        Proposal storage p = _proposals[id];

        if (p.createdAt == 0)       revert ProposalNotFound();
        if (p.executed)             revert ProposalAlreadyExecuted();
        if (p.voted[msg.sender])    revert AlreadyVoted();

        if (block.timestamp > p.createdAt + PROPOSAL_TTL) {
            emit ProposalExpired(id);
            revert ProposalExpiredError();
        }

        p.voted[msg.sender] = true;
        p.voteCount++;

        emit Voted(id, msg.sender);

        uint256 threshold = p.kind == ProposalKind.Pause
            ? pauseThreshold
            : unpauseThreshold;

        if (p.voteCount >= threshold) {
            _execute(id);
        }
    }

    function _execute(uint256 id) internal {
        Proposal storage p = _proposals[id];
        p.executed = true;

        if (p.kind == ProposalKind.Pause) {
            guard.pause(p.duration);
        } else {
            guard.unpause();
        }

        emit ProposalExecuted(id, p.kind);
    }
}
```

---

### ExampleProtocol.sol — Integration

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PauseGuard.sol";

/**
 * @title ExampleProtocol
 * @notice Shows the minimal integration pattern. The protocol contract
 *         depends only on PauseGuard — it has no awareness of the council.
 *
 * Emergency exits (e.g., withdraw) should generally remain active during
 * a pause so users can recover funds.
 */
contract ExampleProtocol {
    PauseGuard public immutable pauseGuard;
    mapping(address => uint256) public balances;

    error ContractPaused();

    modifier whenNotPaused() {
        if (pauseGuard.paused()) revert ContractPaused();
        _;
    }

    constructor(address _pauseGuard) {
        pauseGuard = PauseGuard(_pauseGuard);
    }

    /// @notice Normal operation — blocked when paused.
    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

    /// @notice Emergency exit — intentionally NOT gated by pause.
    ///         Users must always be able to withdraw their own funds.
    function emergencyWithdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

---

## Formal Invariants

The following invariants must hold at all times and should be verified by your formal verification tooling (e.g., Certora Prover, Dafny, Halmos):

```
INV-1  (Pause authority)
       ∀ state s: s.paused = true  →  council.executed(PauseProposal) ∧ voteCount ≥ pauseThreshold

INV-2  (Unpause authority)
       ∀ state s: transition(paused→unpaused)  →  voteCount ≥ unpauseThreshold

INV-3  (Auto-expiry)
       ∀ state s: block.timestamp ≥ s.pauseExpiry  →  paused() = false

INV-4  (Threshold ordering)
       unpauseThreshold > pauseThreshold

INV-5  (No self-pause)
       ¬∃ single_address a: a can cause paused = true without N other guardians

INV-6  (Emergency exit liveness)
       paused = true  →  emergencyWithdraw() does NOT revert due to pause

INV-7  (Proposal expiry)
       block.timestamp > proposal.createdAt + PROPOSAL_TTL  →  proposal cannot be executed
```

---

## State Machine

```
                  ┌─────────────────────────────────┐
                  │                                   │
           ┌──────▼──────┐   pause() by council  ┌──┴──────────┐
           │             ├──────────────────────►│             │
   START──►│  UNPAUSED   │                        │   PAUSED    │
           │             │◄──────────────────────┤             │
           └─────────────┘   unpause() by council └──────┬──────┘
                              (unpauseThreshold)         │
                                                          │ block.timestamp ≥ pauseExpiry
                                                          ▼
                                                   auto-expire → UNPAUSED
```

---

## Attack Surface & Mitigations

| Attack                               | Description                                                                 | Mitigation                                                               |
| ------------------------------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **Guardian key compromise**          | Attacker steals `ceil(N/3)` keys, triggers illegitimate pause               | Pause auto-expires (MAX 7 days); emergency user withdrawal still works   |
| **Griefing via repeated proposals**  | Spam proposals to exhaust gas or confuse UI                                 | Proposals expire in 1 hour; add proposal cooldown per guardian if needed |
| **Collusion to block unpause**       | `ceil(N/3)` colluding guardians refuse to reach `ceil(2N/3)` unpause quorum | Pause TTL forces auto-expiry; no single party can extend indefinitely    |
| **Council address substitution**     | Attacker deploys malicious contract at council address                      | `council` is `immutable`; set correctly at PauseGuard construction       |
| **Pause during withdrawal**          | Pause blocks emergency exit, trapping funds                                 | Emergency exits explicitly bypass the `whenNotPaused` modifier           |
| **Front-running proposal execution** | Attacker watches mempool and front-runs `_execute`                          | Execution is internal and triggered atomically by the final vote         |
| **Stale vote replay**                | Old votes counted after guardian is removed                                 | Guardians are immutable per deployment; rotate by deploying new council  |

---

## Testing Checklist

```
□ Single guardian cannot pause unilaterally
□ Exactly pauseThreshold votes triggers pause execution
□ pauseThreshold − 1 votes does NOT execute
□ Pause auto-expires after duration elapses (manipulate block.timestamp)
□ Post-expiry paused() returns false without explicit unpause call
□ PauseExpired event emitted on first post-expiry whenNotPaused call
□ Unpause requires unpauseThreshold (greater than pauseThreshold)
□ Proposal cannot be executed after PROPOSAL_TTL
□ Duplicate vote from same guardian reverts with AlreadyVoted
□ Non-guardian cannot call proposePause / proposeUnpause / vote
□ emergencyWithdraw() succeeds while paused
□ deposit() reverts while paused
□ pause() reverts if already paused and not expired
□ MAX_PAUSE_DURATION cannot be exceeded by a single pause call
□ All actions emit expected events with correct arguments
□ Fuzz: random guardian vote orderings always reach correct threshold
```

---

## Deployment Checklist

1. **Deploy PauseGuard** with the PauseCouncil address as `_council`. The council is not yet deployed, so use a two-phase deployment or a proxy pattern:
   - Deploy PauseCouncil with a temporary admin address.
   - Deploy PauseGuard with the PauseCouncil address.
   - If using a proxy, finalize the PauseGuard address in PauseCouncil.

2. **Verify guardian addresses** are confirmed multisig keys, not hot wallets.

3. **Verify thresholds** on-chain: `pauseThreshold = ceil(N/3)`, `unpauseThreshold = ceil(2N/3)`.

4. **Verify `council` immutable** in PauseGuard matches deployed PauseCouncil address.

5. **Test pause/unpause round-trip** on testnet with all guardian keys.

6. **Verify emergencyWithdraw** works while paused on testnet.

7. **Publish guardian list** and rotate any keys that appear in prior deployments.

8. **Set up monitoring** alerts for `PauseProposed` and `PauseExecuted` events.

---

## Variant Patterns

### A — Token-Weighted Voting

Replace fixed M-of-N with vote weight proportional to staked tokens. Higher economic stake = more voice. Add slash conditions to punish malicious pause proposals.

### B — Timelocked Unpause

After a pause, require a 24-hour timelock before unpausing. Gives users time to exit before normal operations resume.

### C — Upgradeable Council

Add a `transferCouncil(address newCouncil)` function to PauseGuard, callable only via a governance proposal with a separate high quorum. Allows guardian rotation without redeploying the guard or protocol contracts.

### D — Cross-Chain Pause

Use a message bridge (e.g., LayerZero, Hyperlane) so a pause on the canonical chain automatically propagates to satellite deployments. The bridge message is authenticated by the PauseCouncil address on the source chain.

### E — Circuit Breaker Autopause

Integrate an on-chain oracle or anomaly detector (e.g., unusual outflow rate) that can trigger a pause proposal automatically when thresholds are breached, with guardian ratification required within 1 hour or the auto-pause expires.

---

## References

- OpenZeppelin `Pausable.sol` — single-admin baseline (this pattern extends it to M-of-N)
- [EIP-2535 Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535) — facet-based upgrade pattern compatible with this guard
- Compound Governor Bravo — inspiration for threshold-based proposal lifecycle
- Trail of Bits: _Decentralization Pitfalls in Emergency Stops_ (2023)
- Certora Prover documentation — formal verification of ERC-20 and pause invariants
- OpenZeppelin Defender Sentinels — monitoring `Paused` / `Unpaused` events in production

---

_Pattern version: 1.0.0 — February 2026. Submit improvements via PR to `patterns/pause-mechanism/`._
