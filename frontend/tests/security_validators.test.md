/\*\*

- security-validators.test.ts
-
- Unit tests for the cross-contract security property validators.
-
- Run with: npx jest OR npx vitest run
-
- Test structure:
- CallGraphBuilder
-     ✓ Contract registration
-     ✓ Call site detection
-     ✓ Call type classification (CALL / STATICCALL / DELEGATECALL / LOW_LEVEL)
-     ✓ Edge building
-     ✓ Cycle detection
-
- ReentrancyValidator
-     ✓ Flags state-write-after-call without guard
-     ✓ Does NOT flag CEI-correct code
-     ✓ Does NOT flag nonReentrant-guarded functions
-     ✓ Does NOT flag STATICCALL paths
-     ✓ Elevates to CRITICAL when ETH sent + cycle present
-
- UncheckedReturnValueValidator
-     ✓ Flags low-level call with no return check
-     ✓ Does NOT flag high-level calls
-     ✓ Does NOT flag .call whose result is checked
-
- DelegatecallValidator
-     ✓ CRITICAL for delegatecall to unresolved address
-     ✓ MEDIUM for delegatecall to known contract (layout warning)
-     ✓ Does NOT flag regular CALL
-
- AccessControlValidator
-     ✓ Flags public function calling out with no modifier
-     ✓ Does NOT flag functions with onlyOwner
-     ✓ Does NOT flag internal functions
-
- ETHTransferValidator
-     ✓ Flags .transfer() usage
-     ✓ Flags .send() usage
-     ✓ Flags unchecked .call{value}
-     ✓ Does NOT flag checked .call{value}
-
- OracleManipulationValidator
-     ✓ Flags getPrice() → sensitive state write pattern
-     ✓ Does NOT flag oracle reads with no subsequent state write
-
- CallCycleValidator
-     ✓ Reports cycle with state mutation as HIGH
-     ✓ Does NOT report false cycle on linear call chain
-
- Integration
-     ✓ Full pipeline on VulnerableVault produces ≥1 reentrancy finding
-     ✓ Full pipeline on SafeVault produces 0 reentrancy findings
-     ✓ All findings have required fields populated
  \*/

import { describe, it, expect, beforeEach } from "vitest";
import { CallGraphBuilder, CallGraph } from "../../src/analyzer/CallGraphBuilder";
import {
ReentrancyValidator,
UncheckedReturnValueValidator,
DelegatecallValidator,
AccessControlValidator,
ETHTransferValidator,
OracleManipulationValidator,
CallCycleValidator,
runAllValidators,
ValidationFinding,
} from "../../src/rules/SecurityValidators";
import {
VULNERABLE_VAULT_AST,
SAFE_VAULT_AST,
TOKEN_BRIDGE_AST,
FLASH_LOAN_RECEIVER_AST,
UNSAFE_PROXY_AST,
CROSS_CONTRACT_REENTRANT_AST,
ACCESS_CONTROL_MISSING_AST,
ETH_TRANSFER_BAD_AST,
} from "../fixtures/contracts";

// ─── Helper ───────────────────────────────────────────────────────────────────

function buildGraph(...units: Parameters<CallGraphBuilder["build"]>[0]): CallGraph {
return new CallGraphBuilder().build(units);
}

function findingsFor(ruleId: string, findings: ValidationFinding[]): ValidationFinding[] {
return findings.filter((f) => f.ruleId === ruleId);
}

// ─── CallGraphBuilder ─────────────────────────────────────────────────────────

describe("CallGraphBuilder", () => {
describe("contract registration", () => {
it("registers all contracts in the source units", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
expect(graph.contracts.has("VulnerableVault")).toBe(true);
});

    it("registers state variables on each contract node", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const node = graph.contracts.get("VulnerableVault")!;
      expect(node.stateVariables.some((v) => v.name === "balances")).toBe(true);
    });

    it("registers function definitions", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const node = graph.contracts.get("VulnerableVault")!;
      expect(node.functions.some((f) => f.name === "withdraw")).toBe(true);
    });

    it("detects hasReentrancyGuard = true when nonReentrant modifier present", () => {
      const graph = buildGraph(SAFE_VAULT_AST);
      const fn = graph.contracts.get("SafeVault")!.functions.find((f) => f.name === "withdraw")!;
      expect(fn.hasReentrancyGuard).toBe(true);
    });

    it("detects hasReentrancyGuard = false when no guard modifier present", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const fn = graph.contracts.get("VulnerableVault")!.functions.find((f) => f.name === "withdraw")!;
      expect(fn.hasReentrancyGuard).toBe(false);
    });

    it("registers multiple contracts from a single source unit", () => {
      const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
      expect(graph.contracts.has("FlashLoanReceiver")).toBe(true);
      expect(graph.contracts.has("IOracle")).toBe(true);
    });

    it("registers contracts from multiple source units", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST, SAFE_VAULT_AST);
      expect(graph.contracts.has("VulnerableVault")).toBe(true);
      expect(graph.contracts.has("SafeVault")).toBe(true);
    });

});

describe("call site detection", () => {
it("detects external .call on VulnerableVault.withdraw()", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const sites = graph.callSites.filter((s) => s.callerContract === "VulnerableVault");
expect(sites.length).toBeGreaterThanOrEqual(1);
});

    it("classifies address.call as LOW_LEVEL_CALL", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const site = graph.callSites.find(
        (s) => s.callerContract === "VulnerableVault" && s.callType === "LOW_LEVEL_CALL"
      );
      expect(site).toBeDefined();
    });

    it("classifies address.transfer as TRANSFER", () => {
      const graph = buildGraph(ETH_TRANSFER_BAD_AST);
      const site = graph.callSites.find(
        (s) => s.callerContract === "LegacyPayout" && s.callType === "TRANSFER"
      );
      expect(site).toBeDefined();
    });

    it("classifies address.delegatecall as LOW_LEVEL_DELEGATECALL", () => {
      const graph = buildGraph(UNSAFE_PROXY_AST);
      const site = graph.callSites.find(
        (s) => s.callType === "LOW_LEVEL_DELEGATECALL"
      );
      expect(site).toBeDefined();
    });

    it("classifies IOracle.getPrice as STATICCALL (view function)", () => {
      const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
      const site = graph.callSites.find(
        (s) => s.calleeFunction === "getPrice"
      );
      expect(site).toBeDefined();
      expect(site!.callType).toBe("STATICCALL");
    });

    it("detects sendsValue = true for .call{value:}", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const site = graph.callSites.find(
        (s) => s.callerContract === "VulnerableVault" && s.callType === "LOW_LEVEL_CALL"
      );
      expect(site?.sendsValue).toBe(true);
    });

    it("records stateWritesAfterCall for writes after external call", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      const site = graph.callSites.find(
        (s) => s.callerContract === "VulnerableVault" && s.callType === "LOW_LEVEL_CALL"
      );
      expect(site?.stateWritesAfterCall.length).toBeGreaterThanOrEqual(1);
    });

    it("records empty stateWritesAfterCall for CEI-correct code", () => {
      const graph = buildGraph(SAFE_VAULT_AST);
      const site = graph.callSites.find((s) => s.callerContract === "SafeVault");
      // SafeVault writes balances BEFORE the call
      expect(site?.stateWritesAfterCall.length ?? 0).toBe(0);
    });

});

describe("edge building", () => {
it("creates an edge from PoolA to PoolB", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
const edges = graph.edges.get("PoolA");
expect(edges?.has("PoolB")).toBe(true);
});

    it("creates an edge from PoolB back to PoolA", () => {
      const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
      const edges = graph.edges.get("PoolB");
      expect(edges?.has("PoolA")).toBe(true);
    });

    it("does not create edges for contracts with no outgoing calls", () => {
      const graph = buildGraph(SAFE_VAULT_AST);
      // SafeVault calls msg.sender — address type, not a named contract
      const edges = graph.edges.get("SafeVault");
      expect(edges?.size ?? 0).toBe(0);
    });

});

describe("cycle detection", () => {
it("detects the PoolA ↔ PoolB cycle", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
const hasCycle = graph.cycles.some(
(c) => c.includes("PoolA") && c.includes("PoolB")
);
expect(hasCycle).toBe(true);
});

    it("reports no cycles for a linear call chain", () => {
      const graph = buildGraph(VULNERABLE_VAULT_AST);
      expect(graph.cycles.length).toBe(0);
    });

    it("reports no cycles for a safe single-contract deployment", () => {
      const graph = buildGraph(SAFE_VAULT_AST);
      expect(graph.cycles.length).toBe(0);
    });

});
});

// ─── ReentrancyValidator ──────────────────────────────────────────────────────

describe("ReentrancyValidator", () => {
const validator = new ReentrancyValidator();

it("flags VulnerableVault.withdraw() as reentrancy (state write after call)", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].callSite.callerContract).toBe("VulnerableVault");
expect(findings[0].callSite.callerFunction).toBe("withdraw");
});

it("does NOT flag SafeVault.withdraw() (CEI pattern correct)", () => {
const graph = buildGraph(SAFE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings.length).toBe(0);
});

it("does NOT flag a nonReentrant-guarded function", () => {
const graph = buildGraph(SAFE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});

it("does NOT flag STATICCALL paths", () => {
const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
const reentrancyFindings = findingsFor("SA-SEC-001", validator.validate(graph));
const staticCallFindings = reentrancyFindings.filter(
(f) => f.callSite.callType === "STATICCALL"
);
expect(staticCallFindings).toHaveLength(0);
});

it("assigns severity CRITICAL when ETH is sent and a call cycle exists", () => {
// Build a graph where PoolA sends ETH and has a cycle back to itself
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
// Manually mark the PoolA→PoolB call as value-sending to simulate ETH reentrancy
const site = graph.callSites.find((s) => s.callerContract === "PoolA");
if (site) {
site.sendsValue = true;
site.stateWritesAfterCall = ["balances"]; // ensure post-call write
}
const findings = validator.validate(graph);
const critical = findings.filter((f) => f.severity === "critical");
expect(critical.length).toBeGreaterThanOrEqual(1);
});

it("assigns severity HIGH when ETH is sent but no cycle", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
const high = findings.filter((f) => f.severity === "high");
expect(high.length).toBeGreaterThanOrEqual(1);
});

it("includes the affected state variable names in the description", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings[0].description).toMatch(/balances/);
});

it("tags reentrancy findings with 'CEI'", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings[0].tags).toContain("CEI");
});
});

// ─── UncheckedReturnValueValidator ────────────────────────────────────────────

describe("UncheckedReturnValueValidator", () => {
const validator = new UncheckedReturnValueValidator();

it("flags TokenBridge.relayTokens() — unchecked low-level call", () => {
const graph = buildGraph(TOKEN_BRIDGE_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].callSite.callerContract).toBe("TokenBridge");
});

it("assigns HIGH severity when ETH is sent via unchecked call", () => {
const graph = buildGraph(TOKEN_BRIDGE_AST);
const site = graph.callSites.find((s) => s.callerContract === "TokenBridge");
if (site) site.sendsValue = true;
const findings = validator.validate(graph);
expect(findings[0].severity).toBe("high");
});

it("does NOT flag high-level contract calls (non low-level)", () => {
const graph = buildGraph(ACCESS_CONTROL_MISSING_AST);
// Treasury.drainTo makes a high-level token.transfer() call
const findings = validator.validate(graph);
const bridgeFindings = findings.filter(
(f) => f.callSite.callerContract === "Treasury"
);
expect(bridgeFindings).toHaveLength(0);
});

it("does NOT flag a .call whose result is checked (returnValueChecked = true)", () => {
const graph = buildGraph(TOKEN_BRIDGE_AST);
// Mark the call site as checked
graph.callSites.forEach((s) => {
if (s.callerContract === "TokenBridge") s.returnValueChecked = true;
});
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});
});

// ─── DelegatecallValidator ────────────────────────────────────────────────────

describe("DelegatecallValidator", () => {
const validator = new DelegatecallValidator();

it("assigns CRITICAL severity for delegatecall to unresolved address", () => {
const graph = buildGraph(UNSAFE_PROXY_AST);
const findings = validator.validate(graph);
const critical = findings.filter((f) => f.severity === "critical");
expect(critical.length).toBeGreaterThanOrEqual(1);
});

it("flags UnsafeProxy.execute() with unresolved callee", () => {
const graph = buildGraph(UNSAFE_PROXY_AST);
const findings = validator.validate(graph);
expect(findings[0].callSite.callerContract).toBe("UnsafeProxy");
expect(findings[0].callSite.callerFunction).toBe("execute");
});

it("description mentions 'arbitrary code'", () => {
const graph = buildGraph(UNSAFE_PROXY_AST);
const findings = validator.validate(graph);
expect(findings[0].description).toMatch(/arbitrary code/i);
});

it("assigns MEDIUM for delegatecall to a known contract (storage layout warning)", () => {
// Build a custom graph where UnsafeProxy delegates to a known contract
const graph = buildGraph(UNSAFE_PROXY_AST);
const site = graph.callSites.find(
(s) => s.callType === "LOW_LEVEL_DELEGATECALL"
);
if (site) {
site.calleeContractType = "UnsafeProxy"; // resolve to known contract
graph.contracts.set("Implementation", {
name: "Implementation",
kind: "contract",
stateVariables: [],
functions: [],
inheritsFrom: [],
callSites: [],
incomingCallSites: [],
});
site.calleeContractType = "Implementation";
}
const findings = validator.validate(graph);
const medium = findings.filter((f) => f.severity === "medium");
expect(medium.length).toBeGreaterThanOrEqual(1);
});

it("does NOT flag regular high-level CALL", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});
});

// ─── AccessControlValidator ───────────────────────────────────────────────────

describe("AccessControlValidator", () => {
const validator = new AccessControlValidator();

it("flags Treasury.drainTo() — public with no access control modifier", () => {
const graph = buildGraph(ACCESS_CONTROL_MISSING_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].callSite.callerContract).toBe("Treasury");
expect(findings[0].callSite.callerFunction).toBe("drainTo");
});

it("does NOT flag functions with onlyOwner modifier", () => {
const graph = buildGraph(ACCESS_CONTROL_MISSING_AST);
// Add onlyOwner to drainTo and re-run
const fn = graph.contracts.get("Treasury")!.functions.find((f) => f.name === "drainTo")!;
fn.modifiers.push("onlyOwner");
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});

it("does NOT flag internal functions", () => {
const graph = buildGraph(ACCESS_CONTROL_MISSING_AST);
const fn = graph.contracts.get("Treasury")!.functions.find((f) => f.name === "drainTo")!;
fn.visibility = "internal";
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});

it("assigns HIGH severity for payable + no access control", () => {
const graph = buildGraph(ACCESS_CONTROL_MISSING_AST);
const fn = graph.contracts.get("Treasury")!.functions.find((f) => f.name === "drainTo")!;
fn.stateMutability = "payable";
const findings = validator.validate(graph);
const high = findings.filter((f) => f.severity === "high");
expect(high.length).toBeGreaterThanOrEqual(1);
});
});

// ─── ETHTransferValidator ─────────────────────────────────────────────────────

describe("ETHTransferValidator", () => {
const validator = new ETHTransferValidator();

it("flags LegacyPayout.payout() — uses .transfer()", () => {
const graph = buildGraph(ETH_TRANSFER_BAD_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].callSite.callerContract).toBe("LegacyPayout");
});

it("flags .send() usage", () => {
const graph = buildGraph(ETH_TRANSFER_BAD_AST);
const site = graph.callSites.find((s) => s.callType === "TRANSFER")!;
site.callType = "SEND";
const findings = validator.validate(graph);
expect(findings.some((f) => f.callSite.callType === "SEND")).toBe(true);
});

it("description mentions EIP-1884 and 2300 gas stipend", () => {
const graph = buildGraph(ETH_TRANSFER_BAD_AST);
const findings = validator.validate(graph);
expect(findings[0].description).toMatch(/2300/);
expect(findings[0].description).toMatch(/EIP-1884/);
});

it("flags HIGH severity for unchecked .call{value}", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const site = graph.callSites.find(
(s) => s.callType === "LOW_LEVEL_CALL" && s.sendsValue
);
if (site) site.returnValueChecked = false;
const findings = validator.validate(graph);
const high = findings.filter((f) => f.severity === "high" && f.ruleId === "SA-SEC-005");
expect(high.length).toBeGreaterThanOrEqual(1);
});

it("does NOT flag checked .call{value}", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
graph.callSites.forEach((s) => {
if (s.callType === "LOW_LEVEL_CALL") s.returnValueChecked = true;
});
const findings = validator.validate(graph);
const uncheckedEth = findings.filter(
(f) => f.ruleId === "SA-SEC-005" && f.tags.includes("value-loss")
);
expect(uncheckedEth).toHaveLength(0);
});
});

// ─── OracleManipulationValidator ──────────────────────────────────────────────

describe("OracleManipulationValidator", () => {
const validator = new OracleManipulationValidator();

it("flags FlashLoanReceiver.executeOperation() — getPrice() then balance write", () => {
const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].callSite.callerContract).toBe("FlashLoanReceiver");
});

it("tags finding with 'flash-loan' and 'price-manipulation'", () => {
const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
const findings = validator.validate(graph);
expect(findings[0].tags).toContain("flash-loan");
expect(findings[0].tags).toContain("price-manipulation");
});

it("does NOT flag oracle reads with no subsequent sensitive state write", () => {
const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
// Remove post-call state writes
graph.callSites.forEach((s) => {
if (s.calleeFunction === "getPrice") s.stateWritesAfterCall = [];
});
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});

it("recommendation mentions TWAP", () => {
const graph = buildGraph(FLASH_LOAN_RECEIVER_AST);
const findings = validator.validate(graph);
expect(findings[0].recommendation).toMatch(/TWAP/i);
});
});

// ─── CallCycleValidator ───────────────────────────────────────────────────────

describe("CallCycleValidator", () => {
const validator = new CallCycleValidator();

it("reports the PoolA ↔ PoolB cycle", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
const findings = validator.validate(graph);
expect(findings.length).toBeGreaterThanOrEqual(1);
expect(findings[0].title).toMatch(/PoolA.*PoolB|PoolB.*PoolA/);
});

it("assigns HIGH when a contract in the cycle mutates state", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
// PoolA has stateWritesAfterCall on its outgoing call site
const site = graph.callSites.find((s) => s.callerContract === "PoolA");
if (site) site.stateWritesAfterCall = ["balances"];
const findings = validator.validate(graph);
const high = findings.filter((f) => f.severity === "high");
expect(high.length).toBeGreaterThanOrEqual(1);
});

it("does NOT report a cycle for a linear chain", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const findings = validator.validate(graph);
expect(findings).toHaveLength(0);
});

it("recommendation mentions pull-payment or nonReentrant", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
const findings = validator.validate(graph);
expect(findings[0].recommendation).toMatch(/pull-payment|nonReentrant|reentrancy guard/i);
});
});

// ─── Integration ──────────────────────────────────────────────────────────────

describe("Integration: runAllValidators()", () => {
it("produces at least one reentrancy finding for VulnerableVault", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const results = runAllValidators(graph);
const reentrancyResults = results.find((r) => r.validatorId === "SA-SEC-001");
expect(reentrancyResults?.findings.length).toBeGreaterThanOrEqual(1);
});

it("produces zero reentrancy findings for SafeVault", () => {
const graph = buildGraph(SAFE_VAULT_AST);
const results = runAllValidators(graph);
const reentrancyResults = results.find((r) => r.validatorId === "SA-SEC-001");
expect(reentrancyResults?.findings.length).toBe(0);
});

it("produces at least one critical finding for UnsafeProxy", () => {
const graph = buildGraph(UNSAFE_PROXY_AST);
const results = runAllValidators(graph);
const allFindings = results.flatMap((r) => r.findings);
const critical = allFindings.filter((f) => f.severity === "critical");
expect(critical.length).toBeGreaterThanOrEqual(1);
});

it("every finding has all required fields populated", () => {
const graph = buildGraph(
VULNERABLE_VAULT_AST,
TOKEN_BRIDGE_AST,
UNSAFE_PROXY_AST,
FLASH_LOAN_RECEIVER_AST
);
const results = runAllValidators(graph);
const allFindings = results.flatMap((r) => r.findings);

    for (const finding of allFindings) {
      expect(finding.ruleId).toBeTruthy();
      expect(finding.severity).toMatch(/critical|high|medium|low|info/);
      expect(finding.title).toBeTruthy();
      expect(finding.description.length).toBeGreaterThan(10);
      expect(finding.recommendation.length).toBeGreaterThan(10);
      expect(finding.callSite).toBeDefined();
      expect(finding.callSite.id).toBeTruthy();
      expect(finding.callSite.callerContract).toBeTruthy();
      expect(finding.callSite.callerFunction).toBeTruthy();
      expect(finding.callSite.location.line).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(finding.tags)).toBe(true);
    }

});

it("returns a result entry for every validator", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const results = runAllValidators(graph);
expect(results).toHaveLength(7); // one per validator
});

it("each result records a non-negative durationMs", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST);
const results = runAllValidators(graph);
results.forEach((r) => expect(r.durationMs).toBeGreaterThanOrEqual(0));
});

it("CrossContractReentrant produces both reentrancy and cycle findings", () => {
const graph = buildGraph(CROSS_CONTRACT_REENTRANT_AST);
// Mark PoolA→PoolB as state-mutating to trigger reentrancy validator
const site = graph.callSites.find((s) => s.callerContract === "PoolA");
if (site) site.stateWritesAfterCall = ["balances"];

    const results = runAllValidators(graph);
    const allFindings = results.flatMap((r) => r.findings);

    const hasCycleFinding    = allFindings.some((f) => f.ruleId === "SA-SEC-007");
    const hasReentrantFinding = allFindings.some((f) => f.ruleId === "SA-SEC-001");

    expect(hasCycleFinding).toBe(true);
    expect(hasReentrantFinding).toBe(true);

});

it("finding ruleIds match the validator IDs that produced them", () => {
const graph = buildGraph(VULNERABLE_VAULT_AST, UNSAFE_PROXY_AST);
const results = runAllValidators(graph);
for (const result of results) {
for (const finding of result.findings) {
expect(finding.ruleId).toBe(result.validatorId);
}
}
});
});
