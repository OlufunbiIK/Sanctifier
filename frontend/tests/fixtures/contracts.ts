/**
 * contracts.ts
 *
 * Solidity source strings and their pre-built mock ASTs used by the test suite.
 *
 * Rather than running @solidity-parser/parser in tests (which would require
 * a Node.js build step), we provide hand-crafted minimal ASTs that match
 * exactly what the parser would produce for each snippet.
 *
 * Contracts provided:
 *   1. VulnerableVault       — classic reentrancy (write after call)
 *   2. SafeVault             — correct CEI pattern
 *   3. TokenBridge           — unchecked low-level call return value
 *   4. FlashLoanReceiver     — oracle manipulation
 *   5. UnsafeProxy           — delegatecall to user-controlled address
 *   6. CrossContractReentrant — two contracts forming a reentrancy cycle
 *   7. AccessControlMissing  — public function calling out with no auth
 *   8. ETHTransferBad        — .transfer() usage
 */

import { SourceUnit } from "../analyzer/ASTTypes";

// ─── Helper: build a minimal SourceUnit wrapping contract subNodes ────────────

function makeUnit(name: string, contracts: any[]): SourceUnit {
  return {
    type: "SourceUnit",
    name,
    children: contracts,
  } as unknown as SourceUnit;
}

// ─── 1. VulnerableVault ───────────────────────────────────────────────────────

/**
 * Classic reentrancy:
 *   balances[msg.sender] updated AFTER the external .call{value}
 */
export const VULNERABLE_VAULT_AST: SourceUnit = makeUnit(
  "VulnerableVault.sol",
  [
    {
      type: "ContractDefinition",
      name: "VulnerableVault",
      kind: "contract",
      baseContracts: [],
      subNodes: [
        {
          type: "StateVariableDeclaration",
          variables: [
            {
              name: "balances",
              typeName: {
                type: "UserDefinedTypeName",
                namePath: "mapping(address=>uint256)",
              },
              visibility: "public",
              mutability: "mutable",
            },
          ],
          initialValue: null,
        },
        {
          type: "FunctionDefinition",
          name: "withdraw",
          visibility: "external",
          stateMutability: "nonpayable",
          modifiers: [], // no reentrancy guard
          parameters: [
            {
              name: "amount",
              typeName: { type: "ElementaryTypeName", name: "uint256" },
            },
          ],
          returnParameters: [],
          body: {
            type: "Block",
            statements: [
              // require(balances[msg.sender] >= amount)  — read before call
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: { type: "Identifier", name: "require" },
                  arguments: [
                    {
                      type: "BinaryOperation",
                      operator: ">=",
                      left: { type: "Identifier", name: "balances" },
                      right: { type: "Identifier", name: "amount" },
                    },
                  ],
                  names: [],
                },
              },
              // (bool ok,) = msg.sender.call{value: amount}("")
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: {
                    type: "MemberAccess",
                    expression: { type: "Identifier", name: "msg.sender" },
                    memberName: "call",
                  },
                  arguments: [{ type: "StringLiteral", value: "" }],
                  names: ["value"],
                  loc: {
                    start: { line: 12, column: 8 },
                    end: { line: 12, column: 50 },
                  },
                },
                // NOTE: __parent not set in mock — handled by validator heuristic
              },
              // balances[msg.sender] -= amount   — write AFTER call
              {
                type: "ExpressionStatement",
                expression: {
                  type: "BinaryOperation",
                  operator: "=",
                  left: { type: "Identifier", name: "balances" },
                  right: { type: "Identifier", name: "amount" },
                },
              },
            ],
          },
          loc: { start: { line: 8, column: 0 }, end: { line: 18, column: 1 } },
        },
      ],
    },
  ],
);

// ─── 2. SafeVault ─────────────────────────────────────────────────────────────

/**
 * Correct CEI pattern: balance zeroed BEFORE the external call.
 */
export const SAFE_VAULT_AST: SourceUnit = makeUnit("SafeVault.sol", [
  {
    type: "ContractDefinition",
    name: "SafeVault",
    kind: "contract",
    baseContracts: [],
    subNodes: [
      {
        type: "StateVariableDeclaration",
        variables: [
          {
            name: "balances",
            typeName: {
              type: "UserDefinedTypeName",
              namePath: "mapping(address=>uint256)",
            },
            visibility: "public",
            mutability: "mutable",
          },
        ],
        initialValue: null,
      },
      {
        type: "FunctionDefinition",
        name: "withdraw",
        visibility: "external",
        stateMutability: "nonpayable",
        modifiers: [{ name: "nonReentrant", arguments: null }],
        parameters: [
          {
            name: "amount",
            typeName: { type: "ElementaryTypeName", name: "uint256" },
          },
        ],
        returnParameters: [],
        body: {
          type: "Block",
          statements: [
            // balances[msg.sender] = 0  — write BEFORE call
            {
              type: "ExpressionStatement",
              expression: {
                type: "BinaryOperation",
                operator: "=",
                left: { type: "Identifier", name: "balances" },
                right: { type: "NumberLiteral", number: "0" },
              },
            },
            // msg.sender.call{value: amount}("")
            {
              type: "ExpressionStatement",
              expression: {
                type: "FunctionCall",
                expression: {
                  type: "MemberAccess",
                  expression: { type: "Identifier", name: "msg.sender" },
                  memberName: "call",
                },
                arguments: [],
                names: ["value"],
                loc: {
                  start: { line: 10, column: 8 },
                  end: { line: 10, column: 50 },
                },
              },
            },
          ],
        },
      },
    ],
  },
]);

// ─── 3. TokenBridge — unchecked low-level call ────────────────────────────────

export const TOKEN_BRIDGE_AST: SourceUnit = makeUnit("TokenBridge.sol", [
  {
    type: "ContractDefinition",
    name: "TokenBridge",
    kind: "contract",
    baseContracts: [],
    subNodes: [
      {
        type: "FunctionDefinition",
        name: "relayTokens",
        visibility: "external",
        stateMutability: "nonpayable",
        modifiers: [],
        parameters: [],
        returnParameters: [],
        body: {
          type: "Block",
          statements: [
            {
              type: "ExpressionStatement",
              expression: {
                type: "FunctionCall",
                expression: {
                  type: "MemberAccess",
                  expression: { type: "Identifier", name: "destination" },
                  memberName: "call",
                },
                arguments: [{ type: "StringLiteral", value: "0x" }],
                names: [],
                loc: {
                  start: { line: 8, column: 4 },
                  end: { line: 8, column: 40 },
                },
                // No parent assignment — return value unchecked
              },
            },
          ],
        },
      },
    ],
  },
]);

// ─── 4. FlashLoanReceiver — oracle manipulation ───────────────────────────────

export const FLASH_LOAN_RECEIVER_AST: SourceUnit = makeUnit(
  "FlashLoanReceiver.sol",
  [
    {
      type: "ContractDefinition",
      name: "FlashLoanReceiver",
      kind: "contract",
      baseContracts: [],
      subNodes: [
        {
          type: "StateVariableDeclaration",
          variables: [
            {
              name: "priceOracle",
              typeName: { type: "UserDefinedTypeName", namePath: "IOracle" },
              visibility: "internal",
              mutability: "mutable",
            },
            {
              name: "balances",
              typeName: {
                type: "UserDefinedTypeName",
                namePath: "mapping(address=>uint256)",
              },
              visibility: "public",
              mutability: "mutable",
            },
          ],
          initialValue: null,
        },
        {
          type: "FunctionDefinition",
          name: "executeOperation",
          visibility: "external",
          stateMutability: "nonpayable",
          modifiers: [],
          parameters: [],
          returnParameters: [],
          body: {
            type: "Block",
            statements: [
              // uint price = priceOracle.getPrice()
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: {
                    type: "MemberAccess",
                    expression: { type: "Identifier", name: "priceOracle" },
                    memberName: "getPrice",
                  },
                  arguments: [],
                  names: [],
                  loc: {
                    start: { line: 10, column: 8 },
                    end: { line: 10, column: 40 },
                  },
                },
              },
              // balances[msg.sender] = computed_amount  — write after oracle read
              {
                type: "ExpressionStatement",
                expression: {
                  type: "BinaryOperation",
                  operator: "=",
                  left: { type: "Identifier", name: "balances" },
                  right: { type: "Identifier", name: "computed" },
                },
              },
            ],
          },
        },
      ],
    },
    {
      type: "ContractDefinition",
      name: "IOracle",
      kind: "interface",
      baseContracts: [],
      subNodes: [
        {
          type: "FunctionDefinition",
          name: "getPrice",
          visibility: "external",
          stateMutability: "view",
          modifiers: [],
          parameters: [],
          returnParameters: [
            {
              name: null,
              typeName: { type: "ElementaryTypeName", name: "uint256" },
            },
          ],
          body: null,
        },
      ],
    },
  ],
);

// ─── 5. UnsafeProxy — delegatecall to unresolved address ─────────────────────

export const UNSAFE_PROXY_AST: SourceUnit = makeUnit("UnsafeProxy.sol", [
  {
    type: "ContractDefinition",
    name: "UnsafeProxy",
    kind: "contract",
    baseContracts: [],
    subNodes: [
      {
        type: "FunctionDefinition",
        name: "execute",
        visibility: "external",
        stateMutability: "nonpayable",
        modifiers: [],
        parameters: [
          {
            name: "target",
            typeName: { type: "ElementaryTypeName", name: "address" },
          },
          {
            name: "data",
            typeName: { type: "ElementaryTypeName", name: "bytes" },
          },
        ],
        returnParameters: [],
        body: {
          type: "Block",
          statements: [
            {
              type: "ExpressionStatement",
              expression: {
                type: "FunctionCall",
                expression: {
                  type: "MemberAccess",
                  expression: { type: "Identifier", name: "target" },
                  memberName: "delegatecall",
                },
                arguments: [{ type: "Identifier", name: "data" }],
                names: [],
                loc: {
                  start: { line: 8, column: 4 },
                  end: { line: 8, column: 40 },
                },
              },
            },
          ],
        },
      },
    ],
  },
]);

// ─── 6. CrossContractReentrant — two contracts forming a cycle ────────────────

export const CROSS_CONTRACT_REENTRANT_AST: SourceUnit = makeUnit(
  "CrossContract.sol",
  [
    {
      type: "ContractDefinition",
      name: "PoolA",
      kind: "contract",
      baseContracts: [],
      subNodes: [
        {
          type: "StateVariableDeclaration",
          variables: [
            {
              name: "poolB",
              typeName: { type: "UserDefinedTypeName", namePath: "PoolB" },
              visibility: "internal",
              mutability: "mutable",
            },
            {
              name: "balances",
              typeName: {
                type: "UserDefinedTypeName",
                namePath: "mapping(address=>uint256)",
              },
              visibility: "public",
              mutability: "mutable",
            },
          ],
          initialValue: null,
        },
        {
          type: "FunctionDefinition",
          name: "withdraw",
          visibility: "external",
          stateMutability: "nonpayable",
          modifiers: [],
          parameters: [],
          returnParameters: [],
          body: {
            type: "Block",
            statements: [
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: {
                    type: "MemberAccess",
                    expression: { type: "Identifier", name: "poolB" },
                    memberName: "notify",
                  },
                  arguments: [],
                  names: [],
                  loc: {
                    start: { line: 14, column: 4 },
                    end: { line: 14, column: 30 },
                  },
                },
              },
              {
                type: "ExpressionStatement",
                expression: {
                  type: "BinaryOperation",
                  operator: "=",
                  left: { type: "Identifier", name: "balances" },
                  right: { type: "NumberLiteral", number: "0" },
                },
              },
            ],
          },
        },
      ],
    },
    {
      type: "ContractDefinition",
      name: "PoolB",
      kind: "contract",
      baseContracts: [],
      subNodes: [
        {
          type: "StateVariableDeclaration",
          variables: [
            {
              name: "poolA",
              typeName: { type: "UserDefinedTypeName", namePath: "PoolA" },
              visibility: "internal",
              mutability: "mutable",
            },
          ],
          initialValue: null,
        },
        {
          type: "FunctionDefinition",
          name: "notify",
          visibility: "external",
          stateMutability: "nonpayable",
          modifiers: [],
          parameters: [],
          returnParameters: [],
          body: {
            type: "Block",
            statements: [
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: {
                    type: "MemberAccess",
                    expression: { type: "Identifier", name: "poolA" },
                    memberName: "withdraw",
                  },
                  arguments: [],
                  names: [],
                  loc: {
                    start: { line: 30, column: 4 },
                    end: { line: 30, column: 30 },
                  },
                },
              },
            ],
          },
        },
      ],
    },
  ],
);

// ─── 7. AccessControlMissing ──────────────────────────────────────────────────

export const ACCESS_CONTROL_MISSING_AST: SourceUnit = makeUnit(
  "AccessControlMissing.sol",
  [
    {
      type: "ContractDefinition",
      name: "Treasury",
      kind: "contract",
      baseContracts: [],
      subNodes: [
        {
          type: "StateVariableDeclaration",
          variables: [
            {
              name: "token",
              typeName: { type: "UserDefinedTypeName", namePath: "IERC20" },
              visibility: "internal",
              mutability: "mutable",
            },
            {
              name: "pendingWithdrawals",
              typeName: {
                type: "UserDefinedTypeName",
                namePath: "mapping(address=>uint256)",
              },
              visibility: "public",
              mutability: "mutable",
            },
          ],
          initialValue: null,
        },
        {
          type: "FunctionDefinition",
          name: "drainTo",
          visibility: "public", // public with no modifier — dangerous
          stateMutability: "nonpayable",
          modifiers: [], // missing onlyOwner
          parameters: [
            {
              name: "recipient",
              typeName: { type: "ElementaryTypeName", name: "address" },
            },
          ],
          returnParameters: [],
          body: {
            type: "Block",
            statements: [
              {
                type: "ExpressionStatement",
                expression: {
                  type: "BinaryOperation",
                  operator: "=",
                  left: { type: "Identifier", name: "pendingWithdrawals" },
                  right: { type: "NumberLiteral", number: "0" },
                },
              },
              {
                type: "ExpressionStatement",
                expression: {
                  type: "FunctionCall",
                  expression: {
                    type: "MemberAccess",
                    expression: { type: "Identifier", name: "token" },
                    memberName: "transfer",
                  },
                  arguments: [
                    { type: "Identifier", name: "recipient" },
                    { type: "Identifier", name: "amount" },
                  ],
                  names: [],
                  loc: {
                    start: { line: 15, column: 4 },
                    end: { line: 15, column: 50 },
                  },
                },
              },
            ],
          },
        },
      ],
    },
    {
      type: "ContractDefinition",
      name: "IERC20",
      kind: "interface",
      baseContracts: [],
      subNodes: [
        {
          type: "FunctionDefinition",
          name: "transfer",
          visibility: "external",
          stateMutability: "nonpayable",
          modifiers: [],
          parameters: [],
          returnParameters: [],
          body: null,
        },
      ],
    },
  ],
);

// ─── 8. ETHTransferBad — .transfer() usage ────────────────────────────────────

export const ETH_TRANSFER_BAD_AST: SourceUnit = makeUnit("ETHTransferBad.sol", [
  {
    type: "ContractDefinition",
    name: "LegacyPayout",
    kind: "contract",
    baseContracts: [],
    subNodes: [
      {
        type: "FunctionDefinition",
        name: "payout",
        visibility: "external",
        stateMutability: "nonpayable",
        modifiers: [],
        parameters: [
          {
            name: "recipient",
            typeName: { type: "ElementaryTypeName", name: "address payable" },
          },
          {
            name: "amount",
            typeName: { type: "ElementaryTypeName", name: "uint256" },
          },
        ],
        returnParameters: [],
        body: {
          type: "Block",
          statements: [
            {
              type: "ExpressionStatement",
              expression: {
                type: "FunctionCall",
                expression: {
                  type: "MemberAccess",
                  expression: { type: "Identifier", name: "recipient" },
                  memberName: "transfer",
                },
                arguments: [{ type: "Identifier", name: "amount" }],
                names: [],
                loc: {
                  start: { line: 8, column: 4 },
                  end: { line: 8, column: 35 },
                },
              },
            },
          ],
        },
      },
    ],
  },
]);
