/**
 * CallGraphBuilder.ts
 *
 * Builds a precise inter-contract call graph by parsing Solidity AST nodes.
 * Tracks every external call site, the callee interface, call type
 * (CALL / STATICCALL / DELEGATECALL), and the execution context at the call site
 * (storage state, ETH value, remaining gas).
 *
 * The resulting CallGraph is consumed by all security property validators.
 */

import {
  ContractDefinition,
  FunctionDefinition,
  ExpressionStatement,
  FunctionCall,
  MemberAccess,
  Identifier,
  StateVariableDeclaration,
  ASTNode,
  SourceUnit,
} from "./ASTTypes";

// ─── Public Types ─────────────────────────────────────────────────────────────

export type CallType =
  | "CALL" // msg.sender.call{value:...}(...)  or  IFoo(addr).bar(...)
  | "STATICCALL" // view / pure external calls
  | "DELEGATECALL" // delegatecall — callee shares caller's storage
  | "LOW_LEVEL_CALL" // address.call(bytes)
  | "LOW_LEVEL_DELEGATECALL"
  | "SEND" // address.send(amount)
  | "TRANSFER"; // address.transfer(amount)

export interface CallSite {
  /** Unique ID: `<contractName>.<functionName>@<line>:<col>` */
  id: string;
  callerContract: string;
  callerFunction: string;
  calleeExpression: string; // raw expression string
  calleeContractType: string | null; // resolved interface/contract name, or null if dynamic
  calleeFunction: string | null;
  callType: CallType;
  sendsValue: boolean; // call includes ETH transfer
  valueExpression: string | null;
  gasLimited: boolean; // explicit gas stipend set
  gasExpression: string | null;
  location: SourceLocation;
  /** State variables read before this call site (used for reentrancy analysis) */
  stateReadsBeforeCall: string[];
  /** State variables written before this call site */
  stateWritesBeforeCall: string[];
  /** State variables written after this call site */
  stateWritesAfterCall: string[];
  /** Whether the return value is checked */
  returnValueChecked: boolean;
}

export interface ContractNode {
  name: string;
  kind: "contract" | "interface" | "library" | "abstract";
  stateVariables: StateVarInfo[];
  functions: FunctionInfo[];
  inheritsFrom: string[];
  callSites: CallSite[]; // calls this contract makes OUT to others
  incomingCallSites: CallSite[]; // calls that target this contract
}

export interface StateVarInfo {
  name: string;
  typeName: string;
  visibility: string;
  mutability: string;
}

export interface FunctionInfo {
  name: string;
  visibility: string;
  stateMutability: string;
  modifiers: string[];
  hasReentrancyGuard: boolean;
  parameters: string[];
  returnTypes: string[];
}

export interface SourceLocation {
  file: string;
  line: number;
  column: number;
}

export interface CallGraph {
  contracts: Map<string, ContractNode>;
  callSites: CallSite[];
  /** Directed edges: callerContract → Set<calleeContract> */
  edges: Map<string, Set<string>>;
  /** Cycles in the call graph (potential reentrancy paths) */
  cycles: string[][];
}

// ─── Implementation ───────────────────────────────────────────────────────────

/**
 * Known low-level call method names on address types.
 */
const LOW_LEVEL_CALLS = new Set([
  "call",
  "delegatecall",
  "staticcall",
  "send",
  "transfer",
]);

/**
 * Modifiers that are commonly used as reentrancy guards.
 */
const REENTRANCY_GUARD_MODIFIERS = new Set([
  "nonReentrant",
  "noReentrancy",
  "reentrancyGuard",
  "ReentrancyGuard",
  "nonreentrant",
]);

export class CallGraphBuilder {
  private graph: CallGraph = {
    contracts: new Map(),
    callSites: [],
    edges: new Map(),
    cycles: [],
  };

  /**
   * Entry point. Accepts one or more parsed SourceUnit ASTs.
   */
  build(sourceUnits: SourceUnit[]): CallGraph {
    // Pass 1: register all contract definitions
    for (const unit of sourceUnits) {
      for (const node of unit.children ?? []) {
        if (node.type === "ContractDefinition") {
          this.registerContract(node as ContractDefinition, unit.name);
        }
      }
    }

    // Pass 2: resolve call sites within each contract
    for (const unit of sourceUnits) {
      for (const node of unit.children ?? []) {
        if (node.type === "ContractDefinition") {
          this.resolveCallSites(node as ContractDefinition, unit.name);
        }
      }
    }

    // Pass 3: build edges and detect cycles
    this.buildEdges();
    this.graph.cycles = this.detectCycles();

    return this.graph;
  }

  // ── Pass 1 ──────────────────────────────────────────────────────────────────

  private registerContract(node: ContractDefinition, file: string): void {
    const stateVars: StateVarInfo[] = [];
    const functions: FunctionInfo[] = [];

    for (const child of node.subNodes ?? []) {
      if (child.type === "StateVariableDeclaration") {
        const sv = child as StateVariableDeclaration;
        for (const v of sv.variables ?? []) {
          stateVars.push({
            name: v.name,
            typeName: this.typeNameToString(v.typeName),
            visibility: v.visibility ?? "internal",
            mutability: v.mutability ?? "mutable",
          });
        }
      } else if (child.type === "FunctionDefinition") {
        const fn = child as FunctionDefinition;
        functions.push({
          name: fn.name ?? "<fallback>",
          visibility: fn.visibility ?? "public",
          stateMutability: fn.stateMutability ?? "nonpayable",
          modifiers: (fn.modifiers ?? []).map((m: any) => m.name),
          hasReentrancyGuard: (fn.modifiers ?? []).some((m: any) =>
            REENTRANCY_GUARD_MODIFIERS.has(m.name),
          ),
          parameters: (fn.parameters ?? []).map((p: any) =>
            this.typeNameToString(p.typeName),
          ),
          returnTypes: (fn.returnParameters ?? []).map((p: any) =>
            this.typeNameToString(p.typeName),
          ),
        });
      }
    }

    this.graph.contracts.set(node.name, {
      name: node.name,
      kind: node.kind as ContractNode["kind"],
      stateVariables: stateVars,
      functions,
      inheritsFrom: (node.baseContracts ?? []).map(
        (b: any) => b.baseName?.namePath ?? "",
      ),
      callSites: [],
      incomingCallSites: [],
    });
  }

  // ── Pass 2 ──────────────────────────────────────────────────────────────────

  private resolveCallSites(node: ContractDefinition, file: string): void {
    for (const child of node.subNodes ?? []) {
      if (child.type !== "FunctionDefinition") continue;
      const fn = child as FunctionDefinition;
      const fnName = fn.name ?? "<fallback>";

      // Build ordered list of state variable accesses in this function body
      const { readsBeforeCall, writesBeforeCall, writesAfterCall } =
        this.collectStateAccesses(fn, node.name);

      // Walk the function body for external call expressions
      this.walkNode(fn.body, (exprNode: ASTNode) => {
        if (exprNode.type !== "FunctionCall") return;
        const callExpr = exprNode as FunctionCall;
        const site = this.classifyCallSite(
          callExpr,
          node.name,
          fnName,
          file,
          readsBeforeCall,
          writesBeforeCall,
          writesAfterCall,
        );
        if (!site) return;

        // Register on the caller contract
        const callerNode = this.graph.contracts.get(node.name);
        callerNode?.callSites.push(site);

        // Register on the callee contract (if resolved)
        if (site.calleeContractType) {
          const calleeNode = this.graph.contracts.get(site.calleeContractType);
          calleeNode?.incomingCallSites.push(site);
        }

        this.graph.callSites.push(site);
      });
    }
  }

  private classifyCallSite(
    node: FunctionCall,
    callerContract: string,
    callerFunction: string,
    file: string,
    readsBeforeCall: string[],
    writesBeforeCall: string[],
    writesAfterCall: string[],
  ): CallSite | null {
    const expr = node.expression;
    if (!expr) return null;

    let callType: CallType | null = null;
    let calleeContractType: string | null = null;
    let calleeFunction: string | null = null;
    let calleeExpression = this.nodeToString(expr);
    let sendsValue = false;
    let valueExpression: string | null = null;
    let gasLimited = false;
    let gasExpression: string | null = null;
    let returnValueChecked = this.isReturnValueChecked(node);

    // Extract {value: ..., gas: ...} named args
    for (const named of node.names ?? []) {
      const idx = (node.names ?? []).indexOf(named);
      const arg = (node.arguments ?? [])[idx];
      if (named === "value") {
        sendsValue = true;
        valueExpression = this.nodeToString(arg);
      }
      if (named === "gas") {
        gasLimited = true;
        gasExpression = this.nodeToString(arg);
      }
    }

    // ── Pattern: MemberAccess (e.g. token.transfer(...), addr.call{...}(...))
    if (expr.type === "MemberAccess") {
      const ma = expr as MemberAccess;
      const memberName = ma.memberName;

      if (LOW_LEVEL_CALLS.has(memberName)) {
        callType = this.toLowLevelCallType(memberName);
        calleeContractType = null; // address type — can't resolve statically
        calleeFunction = null;
      } else {
        // High-level call: resolve callee type from expression
        calleeFunction = memberName;
        callType = "CALL";
        calleeContractType = this.resolveExpressionType(
          ma.expression,
          callerContract,
        );
        if (calleeContractType) {
          const calleeNode = this.graph.contracts.get(calleeContractType);
          const calleeFn = calleeNode?.functions.find(
            (f) => f.name === memberName,
          );
          if (
            calleeFn?.stateMutability === "view" ||
            calleeFn?.stateMutability === "pure"
          ) {
            callType = "STATICCALL";
          }
        }
      }
    }

    // ── Pattern: TypeConversion call  e.g. IFoo(addr).bar(...)
    if (expr.type === "FunctionCall") {
      const inner = expr as FunctionCall;
      if (
        inner.expression?.type === "TypeName" ||
        inner.expression?.type === "Identifier"
      ) {
        const typeName = this.nodeToString(inner.expression);
        calleeContractType = typeName;
        callType = "CALL";
      }
    }

    if (!callType) return null; // skip internal calls

    const location: SourceLocation = {
      file,
      line: (node as any).loc?.start?.line ?? 0,
      column: (node as any).loc?.start?.column ?? 0,
    };

    return {
      id: `${callerContract}.${callerFunction}@${location.line}:${location.column}`,
      callerContract,
      callerFunction,
      calleeExpression,
      calleeContractType,
      calleeFunction,
      callType,
      sendsValue,
      valueExpression,
      gasLimited,
      gasExpression,
      location,
      stateReadsBeforeCall: readsBeforeCall,
      stateWritesBeforeCall: writesBeforeCall,
      stateWritesAfterCall: writesAfterCall,
      returnValueChecked,
    };
  }

  // ── Pass 3 ──────────────────────────────────────────────────────────────────

  private buildEdges(): void {
    for (const site of this.graph.callSites) {
      if (!site.calleeContractType) continue;
      if (!this.graph.edges.has(site.callerContract)) {
        this.graph.edges.set(site.callerContract, new Set());
      }
      this.graph.edges.get(site.callerContract)!.add(site.calleeContractType);
    }
  }

  /**
   * Johnson's algorithm simplified: finds all simple cycles via DFS.
   * Returns an array of cycles, where each cycle is an ordered list of
   * contract names forming the loop.
   */
  private detectCycles(): string[][] {
    const cycles: string[][] = [];
    const visited = new Set<string>();
    const stack: string[] = [];

    const dfs = (node: string, start: string): void => {
      visited.add(node);
      stack.push(node);
      for (const neighbor of this.graph.edges.get(node) ?? []) {
        if (neighbor === start && stack.length > 1) {
          cycles.push([...stack]);
        } else if (!visited.has(neighbor)) {
          dfs(neighbor, start);
        }
      }
      stack.pop();
      visited.delete(node);
    };

    for (const contract of this.graph.contracts.keys()) {
      dfs(contract, contract);
    }

    return cycles;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  private collectStateAccesses(
    fn: FunctionDefinition,
    contractName: string,
  ): {
    readsBeforeCall: string[];
    writesBeforeCall: string[];
    writesAfterCall: string[];
  } {
    // Simplified: tracks variable names; a full implementation would use
    // dataflow analysis with SSA form.
    const readsBeforeCall: string[] = [];
    const writesBeforeCall: string[] = [];
    const writesAfterCall: string[] = [];
    let passedCallSite = false;

    const contract = this.graph.contracts.get(contractName);
    const stateVarNames = new Set(
      contract?.stateVariables.map((v) => v.name) ?? [],
    );

    this.walkNode(fn.body, (node: ASTNode) => {
      if (node.type === "FunctionCall") passedCallSite = true;

      if (node.type === "ExpressionStatement") {
        const es = node as ExpressionStatement;
        if (
          es.expression?.type === "BinaryOperation" &&
          es.expression.operator === "="
        ) {
          const lhs = this.nodeToString(es.expression.left);
          if (stateVarNames.has(lhs.split("[")[0].split(".")[0])) {
            if (passedCallSite) writesAfterCall.push(lhs);
            else writesBeforeCall.push(lhs);
          }
        }

        // Read detection (simplified: look for identifiers that match state vars)
        this.walkNode(es.expression, (inner: ASTNode) => {
          if (inner.type === "Identifier") {
            const name = (inner as Identifier).name;
            if (stateVarNames.has(name) && !passedCallSite) {
              readsBeforeCall.push(name);
            }
          }
        });
      }
    });

    return { readsBeforeCall, writesBeforeCall, writesAfterCall };
  }

  private resolveExpressionType(
    expr: ASTNode,
    callerContract: string,
  ): string | null {
    if (!expr) return null;

    if (expr.type === "Identifier") {
      const name = (expr as Identifier).name;
      // Look for a state variable with this name in the caller
      const caller = this.graph.contracts.get(callerContract);
      const sv = caller?.stateVariables.find((v) => v.name === name);
      if (sv) return sv.typeName.replace("[]", "").replace(/\s+/g, "");
      // Check if it's a direct contract reference
      if (this.graph.contracts.has(name)) return name;
    }

    if (expr.type === "MemberAccess") {
      return (expr as MemberAccess).memberName;
    }

    if (expr.type === "FunctionCall") {
      // TypeConversion: IERC20(addr) → IERC20
      const inner = expr as FunctionCall;
      if (inner.expression?.type === "Identifier") {
        const name = (inner.expression as Identifier).name;
        if (this.graph.contracts.has(name)) return name;
      }
    }

    return null;
  }

  private toLowLevelCallType(method: string): CallType {
    switch (method) {
      case "delegatecall":
        return "LOW_LEVEL_DELEGATECALL";
      case "staticcall":
        return "STATICCALL";
      case "send":
        return "SEND";
      case "transfer":
        return "TRANSFER";
      default:
        return "LOW_LEVEL_CALL";
    }
  }

  private isReturnValueChecked(node: FunctionCall): boolean {
    // Heuristic: if the FunctionCall is the direct child of an ExpressionStatement
    // (not assigned or used in a condition), the return value is unchecked.
    const parent = (node as any).__parent;
    if (!parent) return false;
    return (
      parent.type === "VariableDeclarationStatement" ||
      parent.type === "AssignmentExpression" ||
      parent.type === "BinaryOperation" ||
      parent.type === "IfStatement"
    );
  }

  /** Generic pre-order AST walk. Calls `visitor` on every node. */
  private walkNode(
    node: ASTNode | null | undefined,
    visitor: (n: ASTNode) => void,
  ): void {
    if (!node) return;
    visitor(node);
    for (const key of Object.keys(node)) {
      const child = (node as any)[key];
      if (Array.isArray(child)) {
        child.forEach(
          (c) =>
            typeof c === "object" && c !== null && this.walkNode(c, visitor),
        );
      } else if (typeof child === "object" && child !== null && child.type) {
        this.walkNode(child, visitor);
      }
    }
  }

  private typeNameToString(node: any): string {
    if (!node) return "unknown";
    if (node.type === "ElementaryTypeName") return node.name ?? "unknown";
    if (node.type === "UserDefinedTypeName") return node.namePath ?? "unknown";
    if (node.type === "ArrayTypeName")
      return `${this.typeNameToString(node.baseTypeName)}[]`;
    if (node.type === "Mapping")
      return `mapping(${this.typeNameToString(node.keyType)}=>${this.typeNameToString(node.valueType)})`;
    return "unknown";
  }

  private nodeToString(node: ASTNode | null | undefined): string {
    if (!node) return "";
    if ((node as any).name) return (node as any).name;
    if ((node as any).memberName) {
      return `${this.nodeToString((node as MemberAccess).expression)}.${(node as MemberAccess).memberName}`;
    }
    if ((node as any).namePath) return (node as any).namePath;
    if (node.type === "NumberLiteral") return (node as any).number ?? "0";
    if (node.type === "BooleanLiteral") return String((node as any).value);
    return node.type;
  }
}
