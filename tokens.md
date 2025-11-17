# Secure Policy Language (SPL) - Complete Token List

**Team Members:**
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

**University of Technology, Jamaica - CIT4004**

## Token Categories

### 1. Keywords (Reserved Words)
These are reserved words that have special meaning in the language and cannot be used as identifiers.

| Token | Description | Example Usage |
|-------|-------------|---------------|
| `ROLE` | Defines a role | `ROLE Admin {can: *}` |
| `USER` | Defines a user | `USER JaneDoe {role: Developer}` |
| `RESOURCE` | Defines a resource | `RESOURCE DB_Finance {path: "/data/financial"}` |
| `ALLOW` | Permission grant | `ALLOW action: read ON resource: DB_Finance` |
| `DENY` | Permission denial | `DENY action: delete ON resource: /data/*` |
| `IF` | Conditional clause | `IF (time.hour > 9)` |
| `ON` | Resource specification | `ON resource: DB_Finance` |
| `AND` | Logical AND operator | `time.hour > 9 AND time.hour < 17` |
| `OR` | Logical OR operator | `user.role == Admin OR user.role == Developer` |
| `CAN` | Attribute name keyword (role definitions) | `{can: *}` |
| `PATH` | Attribute name keyword (resource definitions) | `{path: "/data/financial"}` |
| `ACTION` | Attribute name keyword (policy definitions) | `action: read, write` |

**Note**: `CAN`, `PATH`, and `ACTION` are recognized as keywords for stricter parsing. They are matched case-insensitively (both `can`/`CAN`, `path`/`PATH`, `action`/`ACTION` are recognized).

### 2. Attribute Names (Identifiers)
These attribute names are treated as regular identifiers (not keywords):
- `role` - Used in user definitions: `{role: Developer}`
- `resource` - Used in policy definitions: `resource: DB_Finance`

### 3. Arithmetic Operators

| Token | Symbol | Description | Precedence |
|-------|--------|-------------|------------|
| `PLUS` | `+` | Addition | Low |
| `MINUS` | `-` | Subtraction | Low |
| `TIMES` | `*` | Multiplication | High |
| `DIVIDE` | `/` | Division | High |

### 3.1 Wildcard Token

| Token | Symbol | Description | Usage |
|-------|--------|-------------|-------|
| `WILDCARD` | `*` | Wildcard (all permissions) | `{can: *}`, `action: *` |

**Note**: The `*` symbol is tokenized as either `WILDCARD` or `TIMES` based on context:
- **WILDCARD**: When used in permission contexts (after `can:`, `action:`, `path:` or inside braces)
- **TIMES**: When used in arithmetic expressions (between numbers/identifiers)
- The lexer uses context-aware detection to automatically determine the correct token type

### 4. Comparison Operators

| Token | Symbol | Description |
|-------|--------|-------------|
| `EQ` | `==` | Equality |
| `NE` | `!=` | Not equal |
| `LT` | `<` | Less than |
| `GT` | `>` | Greater than |
| `LE` | `<=` | Less than or equal |
| `GE` | `>=` | Greater than or equal |

### 5. Punctuation and Delimiters

| Token | Symbol | Description | Usage |
|-------|--------|-------------|-------|
| `LBRACE` | `{` | Left brace | `ROLE Admin {can: *}` |
| `RBRACE` | `}` | Right brace | `ROLE Admin {can: *}` |
| `LPAREN` | `(` | Left parenthesis | `IF (time.hour > 9)` |
| `RPAREN` | `)` | Right parenthesis | `IF (time.hour > 9)` |
| `COLON` | `:` | Colon | `can: *`, `role: Developer` |
| `DOT` | `.` | Dot (attribute access) | `time.hour`, `user.role` |
| `COMMA` | `,` | Comma (separator) | `read, write`, `Admin, Developer` |

### 6. Literals

| Token | Description | Regex Pattern | Example |
|-------|-------------|---------------|---------|
| `IDENTIFIER` | Variable/name identifier | `[a-zA-Z_][a-zA-Z0-9_]*` | `Admin`, `JaneDoe`, `DB_Finance` |
| `NUMBER` | Integer number | `\d+` | `9`, `17`, `100` |
| `STRING` | String literal | `"[^"]*"` | `"/data/financial"`, `"read"` |

### 7. Whitespace and Comments
- Whitespace: Spaces, tabs (ignored by lexer)
- Newlines: Tracked for line number reporting
- Comments: (Future enhancement - not in current grammar)

## Complete Token List (Alphabetical)

```
ACTION, ALLOW, AND, CAN, COLON, COMMA, DENY, DIVIDE, DOT, EQ, GE, GT, 
IDENTIFIER, IF, LBRACE, LE, LPAREN, LT, MINUS, NE, NUMBER, ON, OR, 
PATH, PLUS, RBRACE, RESOURCE, RPAREN, ROLE, STRING, TIMES, USER, WILDCARD
```

**Total: 33 tokens**

## Token Priority Order (Important for Lexer)

Tokens must be matched in this order to avoid conflicts:

1. **Keywords** (must come before IDENTIFIER)
2. **Multi-character operators** (==, !=, <=, >= before single character)
3. **Single-character operators** (+, -, *, /, <, >)
4. **Punctuation** (braces, parentheses, colon, dot, comma)
5. **Literals** (STRING, NUMBER, IDENTIFIER)
6. **Whitespace** (ignored)

## Regular Expression Patterns

See `lexer.py` for complete regex implementations.

