/**
 * ASTTypes.ts
 *
 * Lightweight TypeScript interfaces mirroring the @solidity-parser/parser AST.
 * Using these instead of importing the parser directly keeps this module
 * testable without a full Solidity toolchain.
 */

export interface ASTNode {
  type: string;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

export interface SourceUnit extends ASTNode {
  type: "SourceUnit";
  name: string; // filename
  children: ASTNode[];
}

export interface ContractDefinition extends ASTNode {
  type: "ContractDefinition";
  name: string;
  kind: "contract" | "interface" | "library" | "abstract";
  baseContracts: BaseContract[];
  subNodes: ASTNode[];
}

export interface BaseContract {
  baseName: { namePath: string };
}

export interface FunctionDefinition extends ASTNode {
  type: "FunctionDefinition";
  name: string | null;
  visibility: "public" | "external" | "internal" | "private";
  stateMutability: "pure" | "view" | "payable" | "nonpayable";
  modifiers: ModifierInvocation[];
  parameters: Parameter[];
  returnParameters: Parameter[];
  body: Block | null;
}

export interface Parameter {
  name: string | null;
  typeName: ASTNode;
}

export interface ModifierInvocation {
  name: string;
  arguments: ASTNode[] | null;
}

export interface Block extends ASTNode {
  type: "Block";
  statements: ASTNode[];
}

export interface ExpressionStatement extends ASTNode {
  type: "ExpressionStatement";
  expression: ASTNode;
}

export interface FunctionCall extends ASTNode {
  type: "FunctionCall";
  expression: ASTNode;
  arguments: ASTNode[];
  names: string[];
}

export interface MemberAccess extends ASTNode {
  type: "MemberAccess";
  expression: ASTNode;
  memberName: string;
}

export interface Identifier extends ASTNode {
  type: "Identifier";
  name: string;
}

export interface StateVariableDeclaration extends ASTNode {
  type: "StateVariableDeclaration";
  variables: StateVariableDeclarationStatement[];
  initialValue: ASTNode | null;
}

export interface StateVariableDeclarationStatement {
  name: string;
  typeName: ASTNode;
  visibility: string;
  mutability: string;
}

export interface BinaryOperation extends ASTNode {
  type: "BinaryOperation";
  operator: string;
  left: ASTNode;
  right: ASTNode;
}

export interface IfStatement extends ASTNode {
  type: "IfStatement";
  condition: ASTNode;
  trueBody: ASTNode;
  falseBody: ASTNode | null;
}

export interface EmitStatement extends ASTNode {
  type: "EmitStatement";
  eventCall: FunctionCall;
}

export interface ReturnStatement extends ASTNode {
  type: "ReturnStatement";
  expression: ASTNode | null;
}
