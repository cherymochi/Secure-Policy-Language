# Secure Policy Language (SPL) - AST Node Classes Documentation

**Team Members:**
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

**University of Technology, Jamaica - CIT4004**

This document describes all AST (Abstract Syntax Tree) node classes defined in `ast.py`.

## Overview

The AST represents the structure of parsed SPL programs. Each grammar rule maps to a corresponding node class. The AST is used for:
- **Semantic Analysis**: Type checking, reference validation
- **Code Generation**: Traversing the tree to generate target code
- **LLM Integration**: Converting AST to JSON for security scanning
- **Documentation**: Visualizing parse trees for reports

## Node Class Hierarchy

```
ASTNode (base class)
├── ProgramNode
├── RoleDefNode
├── UserDefNode
├── ResourceDefNode
├── PolicyNode
├── ConditionNode
├── ComparisonNode
├── ArithmeticExprNode
├── UnaryExprNode
├── AttributeAccessNode
├── IdentifierNode
├── NumberNode
├── StringNode
└── WildcardNode
```

## Node Classes

### Base Class

#### `ASTNode`
Base class for all AST nodes. Tracks line numbers for error reporting.

**Attributes:**
- `line_number` (int): Line number in source code

---

### Program Structure

#### `ProgramNode`
Root node representing an entire SPL program.

**Attributes:**
- `declarations` (list): List of declaration nodes (RoleDefNode, UserDefNode, ResourceDefNode, PolicyNode)

**Example:**
```python
ProgramNode(
    declarations=[
        RoleDefNode(...),
        UserDefNode(...),
        PolicyNode(...)
    ]
)
```

---

### Declaration Nodes

#### `RoleDefNode`
Represents a role definition: `ROLE Admin {can: *}`

**Attributes:**
- `name` (str): Role name (e.g., 'Admin')
- `actions` (list): List of action strings or ['*'] for wildcard

**Example:**
```python
RoleDefNode(name="Admin", actions=["*"], line_num=1)
RoleDefNode(name="Developer", actions=["read", "write"], line_num=2)
```

#### `UserDefNode`
Represents a user definition: `USER JaneDoe {role: Developer}`

**Attributes:**
- `name` (str): User name (e.g., 'JaneDoe')
- `role` (str): Role assigned to user (e.g., 'Developer')

**Example:**
```python
UserDefNode(name="JaneDoe", role="Developer", line_num=2)
```

#### `ResourceDefNode`
Represents a resource definition: `RESOURCE DB_Finance {path: "/data/financial"}`

**Attributes:**
- `name` (str): Resource name (e.g., 'DB_Finance')
- `path` (str): Resource path (e.g., '/data/financial')

**Example:**
```python
ResourceDefNode(name="DB_Finance", path="/data/financial", line_num=3)
```

#### `PolicyNode`
Represents a policy definition: `ALLOW action: read ON resource: DB_Finance IF (time.hour > 9)`

**Attributes:**
- `policy_type` (str): 'ALLOW' or 'DENY'
- `actions` (list): List of action strings (e.g., ['read', 'write'])
- `resources` (str): Resource name or path pattern
- `condition` (ConditionNode or None): Optional condition expression

**Example:**
```python
PolicyNode(
    policy_type="ALLOW",
    actions=["read", "write"],
    resources="DB_Finance",
    condition=ComparisonNode(...),
    line_num=4
)
```

---

### Expression Nodes

#### `ConditionNode`
Represents boolean logic: `time.hour > 9 AND time.hour < 17`

**Attributes:**
- `operator` (str): 'AND' or 'OR'
- `left` (ComparisonNode or ConditionNode): Left operand
- `right` (ComparisonNode or ConditionNode): Right operand

**Example:**
```python
ConditionNode(
    operator="AND",
    left=ComparisonNode(operator=">", ...),
    right=ComparisonNode(operator="<", ...),
    line_num=5
)
```

#### `ComparisonNode`
Represents comparison: `time.hour > 9`, `user.role == Admin`

**Attributes:**
- `operator` (str): '==', '!=', '<', '>', '<=', '>='
- `left` (ArithmeticExprNode, AttributeAccessNode, or LiteralNode): Left operand
- `right` (ArithmeticExprNode, AttributeAccessNode, or LiteralNode): Right operand

**Example:**
```python
ComparisonNode(
    operator=">",
    left=AttributeAccessNode("time", "hour"),
    right=NumberNode(9),
    line_num=5
)
```

#### `ArithmeticExprNode`
Represents arithmetic operations: `3 + 4 * 10`, `time.hour * 2`

**Attributes:**
- `operator` (str): '+', '-', '*', '/'
- `left` (ArithmeticExprNode or LiteralNode): Left operand
- `right` (ArithmeticExprNode or LiteralNode): Right operand

**Example:**
```python
ArithmeticExprNode(
    operator="*",
    left=AttributeAccessNode("time", "hour"),
    right=NumberNode(2),
    line_num=6
)
```

#### `UnaryExprNode`
Represents unary operations: `-5`, `+10`

**Attributes:**
- `operator` (str): '+' or '-'
- `operand` (FactorNode or LiteralNode): Operand

**Example:**
```python
UnaryExprNode(operator="-", operand=NumberNode(5), line_num=7)
```

#### `AttributeAccessNode`
Represents attribute access: `time.hour`, `user.role`

**Attributes:**
- `object_name` (str): Object name (e.g., 'time')
- `attribute_name` (str): Attribute name (e.g., 'hour')

**Example:**
```python
AttributeAccessNode(object_name="time", attribute_name="hour", line_num=5)
```

---

### Literal Nodes

#### `IdentifierNode`
Represents identifiers: `Admin`, `JaneDoe`, `DB_Finance`

**Attributes:**
- `value` (str): Identifier string

**Example:**
```python
IdentifierNode(value="Admin", line_num=1)
```

#### `NumberNode`
Represents number literals: `9`, `17`, `100`

**Attributes:**
- `value` (int): Integer value

**Example:**
```python
NumberNode(value=9, line_num=5)
```

#### `StringNode`
Represents string literals: `"/data/financial"`, `"read"`

**Attributes:**
- `value` (str): String value (without quotes)

**Example:**
```python
StringNode(value="/data/financial", line_num=3)
```

#### `WildcardNode`
Represents wildcard: `*` in action lists

**Attributes:**
- `value` (str): Always '*'

**Example:**
```python
WildcardNode(line_num=1)
```

---

## Helper Functions

### `print_ast(node, indent=0, prefix="")`
Pretty-prints the AST tree structure for visualization.

**Usage:**
```python
program = ProgramNode(...)
print_ast(program)
```

**Output:**
```
ProgramNode(4 declarations)
  ├── RoleDefNode(name='Admin', actions=[*])
  ├── UserDefNode(name='JaneDoe', role='Developer')
  └── PolicyNode(...)
```

### `ast_to_dict(node)`
Converts AST node to dictionary representation for JSON serialization and LLM integration.

**Usage:**
```python
import json
program = ProgramNode(...)
ast_dict = ast_to_dict(program)
json_str = json.dumps(ast_dict, indent=2)
```

## Example: Complete AST

For this SPL code:
```spl
ROLE Admin {can: *}
USER JaneDoe {role: Developer}
RESOURCE DB_Finance {path: "/data/financial"}
ALLOW action: read, write ON resource: DB_Finance
IF (time.hour > 9 AND time.hour < 17)
```

The AST structure:
```
ProgramNode
├── RoleDefNode(name='Admin', actions=['*'])
├── UserDefNode(name='JaneDoe', role='Developer')
├── ResourceDefNode(name='DB_Finance', path='/data/financial')
└── PolicyNode(type='ALLOW', actions=['read', 'write'], ...)
    └── ConditionNode(operator='AND')
        ├── ComparisonNode(operator='>')
        │   ├── AttributeAccessNode('time', 'hour')
        │   └── NumberNode(9)
        └── ComparisonNode(operator='<')
            ├── AttributeAccessNode('time', 'hour')
            └── NumberNode(17)
```

## Usage in Parser

The parser (`parser.py`) will create these nodes when parsing SPL code:

```python
# In parser rules:
def p_role_def(p):
    'role_def : ROLE IDENTIFIER LBRACE role_attributes RBRACE'
    p[0] = RoleDefNode(name=p[2].value, actions=p[4], line_num=p.lineno(1))

def p_policy_def(p):
    'policy_def : policy_type action_clause ON resource_clause IF condition'
    p[0] = PolicyNode(
        policy_type=p[1],
        actions=p[2],
        resources=p[4],
        condition=p[6],
        line_num=p.lineno(1)
    )
```

## Integration with Other Components

1. **Parser**: Creates AST nodes during parsing
2. **Semantic Analyzer**: Traverses AST to check types, validate references
3. **Code Generator**: Traverses AST to generate target code (JSON/Python)
4. **LLM Scanner**: Uses `ast_to_dict()` to convert AST to JSON for security analysis

## Testing

Run `python ast.py` to see example AST creation and visualization.

