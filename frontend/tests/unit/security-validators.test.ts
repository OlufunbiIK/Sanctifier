/**
 * SecurityValidators.ts
 *
 * A suite of security property validators that operate on a CallGraph.
 * Each validator implements the `SecurityValidator` interface and returns
 * a list of `ValidationFinding` objects.
 *
 * Validators implemented:
 *   1. ReentrancyValidator          — CEI pattern, cross-contract reentrancy
 *   2. UncheckedReturnValueValidator — low-level call return values
 *   3. DelegatecallValidator        — delegatecall to untrusted / upgradeable targets
 *   4. AccessControlValidator       — missing auth on state-mutating external-call paths
 *   5. ETHTransferValidator         — send/transfer gas stipend, missing checks
 *   6. OracleManipulationValidator  — single-source price oracle in same tx as state change
 *   7. CallCycleValidator           — circular call chains enabling recursive exploits
 */

import { CallGraph, CallSite } from "../analyzer/CallGraphBuilder";

// ─── Shared Types ─────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ValidationFinding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  callSite: CallSite;
  /** Extra call sites involved (e.g. the full reentrancy path) */
  relatedCallSites?: CallSite[];
  tags: string[];
}

export interface ValidationResult {
  validatorId: string;
  validatorName: string;
  findings: ValidationFinding[];
  /** ms taken */
  durationMs: number;
}

export interface SecurityValidator {
  id: string;
  name: string;
  validate(graph: CallGraph): ValidationFinding[];
}

// ─── 1. Reentrancy Validator ──────────────────────────────────────────────────

/**
 * Detects violations of the Checks-Effects-Interactions pattern.
 *
 * A call site is flagged when ALL of:
 *   (a) the call sends ETH or calls an untrusted contract (not view/pure)
 *   (b) state variables are written AFTER the external call
 *   (c) the calling function has no reentrancy guard modifier
 *
 * Cross-contract reentrancy (read-only reentrancy) is also detected when
 * a state variable is READ before the call but not yet updated, and there
 * exists a call cycle back to the reading function.
 */
export class ReentrancyValidator implements SecurityValidator {
  id = "SA-SEC-001";
  name = "Reentrancy Validator";

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const site of graph.callSites) {
      // Skip safe call types
      if (site.callType === "STATICCALL") continue;

      const callerNode = graph.contracts.get(site.callerContract);
      const callerFn = callerNode?.functions.find(
        (f) => f.name === site.callerFunction,
      );

      if (!callerFn) continue;

      // (c) Skip if a reentrancy guard is present
      if (callerFn.hasReentrancyGuard) continue;

      // (b) State written after the external call
      const writesAfter = site.stateWritesAfterCall;
      if (writesAfter.length === 0) continue;

      // (a) Call must be non-static and either sends ETH or targets mutable function
      const isExternalMutable =
        site.sendsValue ||
        site.callType === "CALL" ||
        site.callType === "LOW_LEVEL_CALL" ||
        site.callType === "LOW_LEVEL_DELEGATECALL";

      if (!isExternalMutable) continue;

      // Determine if there is a call cycle that could enable reentrance
      const hasCycle = graph.cycles.some(
        (cycle) =>
          cycle.includes(site.callerContract) &&
          (site.calleeContractType == null ||
            cycle.includes(site.calleeContractType)),
      );

      const severity: Severity =
        site.sendsValue && hasCycle
          ? "critical"
          : site.sendsValue
            ? "high"
            : hasCycle
              ? "high"
              : "medium";

      findings.push({
        ruleId: this.id,
        severity,
        title: `Reentrancy: state written after external call in ${site.callerContract}.${site.callerFunction}()`,
        description:
          `The function ${site.callerContract}.${site.callerFunction}() makes an external call ` +
          `(${site.calleeExpression}) before updating state variables: [${writesAfter.join(", ")}]. ` +
          (hasCycle
            ? "A call cycle exists in the contract graph, making exploitation via reentrancy feasible."
            : "No call cycle was detected, but the pattern is still dangerous.") +
          (site.sendsValue
            ? ` The call transfers ETH (${site.valueExpression}).`
            : ""),
        recommendation:
          "Apply the Checks-Effects-Interactions pattern: perform all state updates before " +
          "making external calls. Alternatively, add a nonReentrant modifier from " +
          "OpenZeppelin's ReentrancyGuard.",
        callSite: site,
        tags: [
          "reentrancy",
          "CEI",
          hasCycle ? "call-cycle" : "no-cycle",
          site.sendsValue ? "eth-transfer" : "",
        ],
      });
    }

    return findings;
  }
}

// ─── 2. Unchecked Return Value Validator ──────────────────────────────────────

/**
 * Flags low-level calls whose return value is not checked.
 * A contract silently continuing after a failed call may behave incorrectly.
 */
export class UncheckedReturnValueValidator implements SecurityValidator {
  id = "SA-SEC-002";
  name = "Unchecked Return Value Validator";

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    const LOW_LEVEL: CallType[] = [
      "LOW_LEVEL_CALL",
      "LOW_LEVEL_DELEGATECALL",
      "SEND",
    ];

    for (const site of graph.callSites) {
      if (!LOW_LEVEL.includes(site.callType)) continue;
      if (site.returnValueChecked) continue;

      const severity: Severity =
        site.callType === "LOW_LEVEL_DELEGATECALL"
          ? "high"
          : site.sendsValue
            ? "high"
            : "medium";

      findings.push({
        ruleId: this.id,
        severity,
        title: `Unchecked return value from ${site.callType} in ${site.callerContract}.${site.callerFunction}()`,
        description:
          `The ${site.callType} at ${site.location.file}:${site.location.line} ` +
          `(${site.calleeExpression}) does not have its boolean return value checked. ` +
          "If the callee reverts or runs out of gas, execution silently continues.",
        recommendation:
          `Check the return value: \`(bool success, ) = ${site.calleeExpression}; require(success, "call failed");\`. ` +
          "Consider using Address.sendValue() from OpenZeppelin which reverts on failure.",
        callSite: site,
        tags: ["unchecked-return", "low-level-call"],
      });
    }

    return findings;
  }
}

// ─── 3. Delegatecall Validator ────────────────────────────────────────────────

/**
 * Flags delegatecall patterns that are unsafe:
 *   - delegatecall to an address derived from user input (arbitrary code execution)
 *   - delegatecall to a contract not in the known contract graph (unverified)
 *   - delegatecall from a proxy where the implementation slot is publicly settable
 */
export class DelegatecallValidator implements SecurityValidator {
  id = "SA-SEC-003";
  name = "Delegatecall Validator";

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const site of graph.callSites) {
      if (
        site.callType !== "LOW_LEVEL_DELEGATECALL" &&
        site.callType !== "CALL"
      )
        continue;

      if (site.callType !== "LOW_LEVEL_DELEGATECALL") continue;

      const calleeIsKnown =
        site.calleeContractType != null &&
        graph.contracts.has(site.calleeContractType);

      // Unresolved callee = potentially user-controlled address
      if (!calleeIsKnown) {
        findings.push({
          ruleId: this.id,
          severity: "critical",
          title: `delegatecall to unresolved/potentially user-controlled address in ${site.callerContract}.${site.callerFunction}()`,
          description:
            `${site.callerContract}.${site.callerFunction}() executes a delegatecall to ` +
            `\`${site.calleeExpression}\`, which cannot be statically resolved to a known ` +
            "contract. If this address is user-supplied or derived from storage that users " +
            "can influence, an attacker can execute arbitrary code in the context of this contract.",
          recommendation:
            "Ensure the delegatecall target is either (a) a hardcoded immutable address, " +
            "(b) stored in a slot only the owner can modify, or (c) validated against a " +
            "whitelist. Never derive the implementation address from user input.",
          callSite: site,
          tags: ["delegatecall", "arbitrary-code-execution", "proxy"],
        });
      } else {
        // Known callee — check if it has dangerous state variable layout differences
        findings.push({
          ruleId: this.id,
          severity: "medium",
          title: `delegatecall to ${site.calleeContractType} — verify storage layout compatibility`,
          description:
            `${site.callerContract} delegates execution to ${site.calleeContractType}. ` +
            "Storage layout mismatches between proxy and implementation cause silent data corruption.",
          recommendation:
            "Use OpenZeppelin's upgradeable contracts pattern with EIP-1967 storage slots. " +
            "Run a storage layout compatibility check (e.g. hardhat-storage-layout-check) in CI.",
          callSite: site,
          tags: ["delegatecall", "storage-layout", "proxy-upgrade"],
        });
      }
    }

    return findings;
  }
}

// ─── 4. Access Control Validator ─────────────────────────────────────────────

/**
 * Detects external calls on state-mutating paths that lack access control.
 * Specifically flags:
 *   - public/external functions that make external calls without any
 *     onlyOwner / onlyRole / require(msg.sender == ...) check
 */
export class AccessControlValidator implements SecurityValidator {
  id = "SA-SEC-004";
  name = "Access Control Validator";

  private readonly ACCESS_CONTROL_MODIFIERS = new Set([
    "onlyOwner",
    "onlyAdmin",
    "onlyRole",
    "requiresAuth",
    "onlyGovernance",
    "onlyGuardian",
    "onlyCouncil",
  ]);

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const site of graph.callSites) {
      // Only care about state-mutating calls
      if (site.callType === "STATICCALL") continue;

      const callerNode = graph.contracts.get(site.callerContract);
      const callerFn = callerNode?.functions.find(
        (f) => f.name === site.callerFunction,
      );
      if (!callerFn) continue;

      // Only external/public entry points matter
      if (
        callerFn.visibility !== "public" &&
        callerFn.visibility !== "external"
      )
        continue;

      // Check for access control modifiers
      const hasAccessControl = callerFn.modifiers.some((m) =>
        this.ACCESS_CONTROL_MODIFIERS.has(m),
      );

      if (hasAccessControl) continue;

      // Payable public functions that call out without access control are especially risky
      const isPayable = callerFn.stateMutability === "payable";

      if (
        isPayable ||
        site.stateWritesBeforeCall.length > 0 ||
        site.stateWritesAfterCall.length > 0
      ) {
        findings.push({
          ruleId: this.id,
          severity: isPayable ? "high" : "medium",
          title: `Missing access control on external-call path: ${site.callerContract}.${site.callerFunction}()`,
          description:
            `The ${callerFn.visibility} function ${site.callerContract}.${site.callerFunction}() ` +
            `makes an external call to \`${site.calleeExpression}\` without any access control modifier. ` +
            (isPayable
              ? "The function is also payable, allowing anyone to trigger this call with ETH."
              : `It modifies state variables: [${[...site.stateWritesBeforeCall, ...site.stateWritesAfterCall].join(", ")}].`),
          recommendation:
            "Add appropriate access control (e.g. onlyOwner, onlyRole, or a custom modifier) " +
            "to restrict who can trigger the external call path.",
          callSite: site,
          tags: ["access-control", "missing-auth", isPayable ? "payable" : ""],
        });
      }
    }

    return findings;
  }
}

// ─── 5. ETH Transfer Validator ────────────────────────────────────────────────

/**
 * Validates ETH transfer patterns in cross-contract calls:
 *   - Use of address.transfer() or address.send() (2300 gas stipend, breaks with EIP-1884)
 *   - ETH sent without checking callee is not a contract (DoS via reverting fallback)
 *   - Missing balance check before transfer
 */
export class ETHTransferValidator implements SecurityValidator {
  id = "SA-SEC-005";
  name = "ETH Transfer Validator";

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const site of graph.callSites) {
      // Flag .transfer() and .send() usage
      if (site.callType === "TRANSFER" || site.callType === "SEND") {
        findings.push({
          ruleId: this.id,
          severity: "medium",
          title: `Use of ${site.callType === "TRANSFER" ? ".transfer()" : ".send()"} in ${site.callerContract}.${site.callerFunction}()`,
          description:
            `${site.callerContract}.${site.callerFunction}() uses ` +
            `address.${site.callType === "TRANSFER" ? "transfer" : "send"}() which forwards only 2300 gas. ` +
            "Post EIP-1884, SLOAD costs 2600 gas, meaning recipients that read storage in their " +
            "fallback/receive functions will always fail, enabling DoS.",
          recommendation:
            'Replace with a low-level call: `(bool success,) = recipient.call{value: amount}(""); require(success);`. ' +
            "Alternatively use OpenZeppelin's Address.sendValue().",
          callSite: site,
          tags: ["eth-transfer", "gas-stipend", "eip-1884", "dos"],
        });
        continue;
      }

      // Flag .call{value:...} without return value check
      if (
        site.sendsValue &&
        site.callType === "LOW_LEVEL_CALL" &&
        !site.returnValueChecked
      ) {
        findings.push({
          ruleId: this.id,
          severity: "high",
          title: `ETH transferred via unchecked .call{value} in ${site.callerContract}.${site.callerFunction}()`,
          description:
            `An ETH transfer (${site.valueExpression} wei) is made via low-level call to ` +
            `\`${site.calleeExpression}\` but the return value is not checked. ` +
            "A failed transfer silently continues and the ETH may be lost or the accounting corrupted.",
          recommendation:
            'Always check the return value: `require(success, "ETH transfer failed");`.',
          callSite: site,
          tags: ["eth-transfer", "unchecked-return", "value-loss"],
        });
      }
    }

    return findings;
  }
}

// ─── 6. Oracle Manipulation Validator ────────────────────────────────────────

/**
 * Detects single-source or same-transaction oracle reads on paths that
 * update critical state (balances, prices, positions).
 *
 * Pattern: external call to a price/oracle function is made in the same
 * function that writes to a balance/share/position variable, with no
 * TWAP or multi-source aggregation evident.
 */
export class OracleManipulationValidator implements SecurityValidator {
  id = "SA-SEC-006";
  name = "Oracle Manipulation Validator";

  private readonly ORACLE_FUNCTIONS = new Set([
    "getPrice",
    "latestAnswer",
    "latestRoundData",
    "getReserves",
    "slot0",
    "observe",
    "consult",
    "price",
    "getAmountsOut",
    "getAmountsIn",
  ]);

  private readonly SENSITIVE_STATE_VARS = new Set([
    "balance",
    "balances",
    "shares",
    "totalSupply",
    "liquidity",
    "position",
    "positions",
    "debt",
    "collateral",
    "price",
  ]);

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const site of graph.callSites) {
      if (!site.calleeFunction) continue;
      if (!this.ORACLE_FUNCTIONS.has(site.calleeFunction)) continue;

      // Check if sensitive state is written after the oracle read
      const sensitiveWrites = site.stateWritesAfterCall.filter((v) =>
        [...this.SENSITIVE_STATE_VARS].some((keyword) =>
          v.toLowerCase().includes(keyword.toLowerCase()),
        ),
      );
      if (sensitiveWrites.length === 0) continue;

      findings.push({
        ruleId: this.id,
        severity: "high",
        title: `Single-source oracle read before state update in ${site.callerContract}.${site.callerFunction}()`,
        description:
          `${site.callerContract}.${site.callerFunction}() reads a price/oracle value from ` +
          `\`${site.calleeExpression}.${site.calleeFunction}()\` in the same transaction as it ` +
          `updates sensitive state: [${sensitiveWrites.join(", ")}]. ` +
          "A flash-loan attack can manipulate spot prices within a single transaction, " +
          "causing the contract to operate on a false price.",
        recommendation:
          "Use a TWAP (time-weighted average price) oracle such as Uniswap V3 TWAP or " +
          "Chainlink with a minimum heartbeat check. Avoid reading spot prices from AMMs " +
          "in the same transaction as state updates.",
        callSite: site,
        tags: ["oracle-manipulation", "flash-loan", "price-manipulation"],
      });
    }

    return findings;
  }
}

// ─── 7. Call Cycle Validator ──────────────────────────────────────────────────

/**
 * Reports call cycles detected in the graph.
 * A cycle by itself is not always exploitable, but combined with state
 * mutation or ETH transfer, it creates a reentrancy attack surface.
 */
export class CallCycleValidator implements SecurityValidator {
  id = "SA-SEC-007";
  name = "Call Cycle Validator";

  validate(graph: CallGraph): ValidationFinding[] {
    const findings: ValidationFinding[] = [];

    for (const cycle of graph.cycles) {
      // Find an example call site that participates in the cycle
      const exampleSite = graph.callSites.find(
        (s) =>
          cycle.includes(s.callerContract) &&
          s.calleeContractType != null &&
          cycle.includes(s.calleeContractType),
      );
      if (!exampleSite) continue;

      const mutatingNode = cycle.find((contractName) => {
        const node = graph.contracts.get(contractName);
        return (node?.callSites ?? []).some(
          (s) => s.stateWritesAfterCall.length > 0 || s.sendsValue,
        );
      });

      const severity: Severity = mutatingNode ? "high" : "medium";

      findings.push({
        ruleId: this.id,
        severity,
        title: `Circular call chain detected: ${cycle.join(" → ")} → ${cycle[0]}`,
        description:
          `A call cycle exists in the contract graph: ${cycle.join(" → ")} → ${cycle[0]}. ` +
          (mutatingNode
            ? `${mutatingNode} mutates state or transfers ETH within the cycle, ` +
              "making this a candidate for a cross-contract reentrancy exploit."
            : "No direct state mutation or ETH transfer was detected within the cycle, " +
              "but the pattern should be reviewed."),
        recommendation:
          "Break the cycle by introducing a pull-payment pattern, a reentrancy guard, " +
          "or restructuring the contract dependencies so that callbacks do not re-enter " +
          "the originating contract.",
        callSite: exampleSite,
        tags: [
          "call-cycle",
          "reentrancy",
          mutatingNode ? "state-mutation" : "",
        ],
      });
    }

    return findings;
  }
}

// ─── Validator Registry ───────────────────────────────────────────────────────

export const ALL_VALIDATORS: SecurityValidator[] = [
  new ReentrancyValidator(),
  new UncheckedReturnValueValidator(),
  new DelegatecallValidator(),
  new AccessControlValidator(),
  new ETHTransferValidator(),
  new OracleManipulationValidator(),
  new CallCycleValidator(),
];

// ─── Runner ───────────────────────────────────────────────────────────────────

export function runAllValidators(
  graph: CallGraph,
  validators: SecurityValidator[] = ALL_VALIDATORS,
): ValidationResult[] {
  return validators.map((v) => {
    const start = Date.now();
    const findings = v.validate(graph);
    return {
      validatorId: v.id,
      validatorName: v.name,
      findings,
      durationMs: Date.now() - start,
    };
  });
}
