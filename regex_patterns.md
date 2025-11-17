# Secure Policy Language (SPL) - Regular Expression Patterns

**Team Members:**
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

**University of Technology, Jamaica - CIT4004**

This document provides a complete reference of all regular expressions used in the SPL lexer to recognize tokens.

## Token Recognition Order

**Important**: PLY matches tokens in the order they are defined. Multi-character patterns must be defined before single-character patterns to avoid conflicts.

## 1. Keywords (Reserved Words)

Most keywords are case-sensitive and must match exactly. Attribute name keywords (`CAN`, `PATH`, `ACTION`) support case-insensitive matching.

| Token | Regex Pattern | Description | Example |
|-------|---------------|-------------|---------|
| `ROLE` | `r'ROLE'` | Role definition keyword | `ROLE Admin` |
| `USER` | `r'USER'` | User definition keyword | `USER JaneDoe` |
| `RESOURCE` | `r'RESOURCE'` | Resource definition keyword | `RESOURCE DB_Finance` |
| `ALLOW` | `r'ALLOW'` | Permission grant keyword | `ALLOW action: read` |
| `DENY` | `r'DENY'` | Permission denial keyword | `DENY action: delete` |
| `IF` | `r'IF'` | Conditional clause keyword | `IF (condition)` |
| `ON` | `r'ON'` | Resource specification keyword | `ON resource: DB_Finance` |
| `AND` | `r'AND'` | Logical AND operator | `A AND B` |
| `OR` | `r'OR'` | Logical OR operator | `A OR B` |
| `CAN` | `r'[Cc][Aa][Nn]'` | Attribute name keyword (role definitions) | `{can: *}` or `{CAN: *}` |
| `PATH` | `r'[Pp][Aa][Tt][Hh]'` | Attribute name keyword (resource definitions) | `{path: "/data"}` or `{PATH: "/data"}` |
| `ACTION` | `r'[Aa][Cc][Tt][Ii][Oo][Nn]'` | Attribute name keyword (policy definitions) | `action: read` or `ACTION: read` |

**Implementation Note**: 
- Standard keywords are matched as functions (e.g., `def t_ROLE(t)`) before the IDENTIFIER pattern to ensure they are recognized as keywords, not identifiers.
- Attribute name keywords (`CAN`, `PATH`, `ACTION`) use case-insensitive regex patterns and normalize values to uppercase.

## 2. Comparison Operators

Multi-character operators must be defined before single-character operators.

| Token | Regex Pattern | Description | Example |
|-------|---------------|-------------|---------|
| `GE` | `r'>='` | Greater than or equal | `time.hour >= 9` |
| `LE` | `r'<='` | Less than or equal | `time.hour <= 17` |
| `EQ` | `r'=='` | Equality comparison | `user.role == Admin` |
| `NE` | `r'!='` | Not equal comparison | `user.role != Guest` |
| `GT` | `r'>'` | Greater than | `time.hour > 9` |
| `LT` | `r'<'` | Less than | `time.hour < 17` |

**Implementation Note**: `>=` and `<=` must be defined before `>` and `<` to avoid matching the first character only.

## 3. Arithmetic Operators

| Token | Regex Pattern | Description | Precedence | Example |
|-------|---------------|-------------|------------|---------|
| `PLUS` | `r'\+'` | Addition | Low | `3 + 4` |
| `MINUS` | `r'-'` | Subtraction | Low | `10 - 5` |
| `TIMES` | `r'\*'` | Multiplication | High | `3 * 4` |
| `DIVIDE` | `r'/'` | Division | High | `10 / 2` |

**Special Note on `*` (TIMES/WILDCARD)**:
- The `*` symbol is used for both multiplication (`3 * 4`) and wildcard permissions (`{can: *}`)
- The lexer uses **context-aware detection** to automatically determine the correct token type:
  - **WILDCARD**: When `*` appears after attribute keywords (`can:`, `action:`, `path:`) or inside braces
  - **TIMES**: When `*` appears between numbers/identifiers in arithmetic expressions
- The lexer examines surrounding characters (before and after `*`) to determine context
- Examples:
  - `{can: *}` → `WILDCARD` (after colon, inside braces)
  - `action: *` → `WILDCARD` (after attribute keyword)
  - `3 * 4` → `TIMES` (between numbers)
  - `time.hour * 2` → `TIMES` (between identifier and number)

## 4. Punctuation and Delimiters

| Token | Regex Pattern | Description | Example Usage |
|-------|---------------|-------------|---------------|
| `LBRACE` | `r'\{'` | Left brace | `ROLE Admin {can: *}` |
| `RBRACE` | `r'\}'` | Right brace | `ROLE Admin {can: *}` |
| `LPAREN` | `r'\('` | Left parenthesis | `IF (time.hour > 9)` |
| `RPAREN` | `r'\)'` | Right parenthesis | `IF (time.hour > 9)` |
| `COLON` | `r':'` | Colon (attribute separator) | `can: *`, `role: Developer` |
| `DOT` | `r'\.'` | Dot (attribute access) | `time.hour`, `user.role` |
| `COMMA` | `r','` | Comma (list separator) | `read, write` |

**Escape Characters**: Braces, parentheses, and dot are escaped in regex (`\{`, `\}`, `\(`, `\)`, `\.`) because they have special meaning in regular expressions.

## 5. Literals

### 5.1 Identifiers

**Pattern**: `r'[a-zA-Z_][a-zA-Z0-9_]*'`

**Description**: 
- Must start with a letter (a-z, A-Z) or underscore (_)
- Can contain letters, digits (0-9), and underscores
- Case-sensitive

**Examples**:
- Valid: `Admin`, `JaneDoe`, `DB_Finance`, `time`, `hour`, `role`, `resource`
- Invalid: `123abc` (starts with digit), `my-name` (contains hyphen)
- Note: `can`, `path`, and `action` are recognized as `CAN`, `PATH`, and `ACTION` tokens (not IDENTIFIER)

**Implementation**: The identifier function checks if the matched string is a keyword (case-insensitive for `CAN`, `PATH`, `ACTION`). If it is, the token type is changed to the keyword type. Otherwise, it remains `IDENTIFIER`.

### 5.2 Numbers

**Pattern**: `r'\d+'`

**Description**:
- One or more digits (0-9)
- Currently supports only integers (no decimals)
- Converted to Python `int` type during tokenization

**Examples**:
- Valid: `0`, `9`, `17`, `100`, `12345`
- Invalid: `3.14` (decimal not supported yet), `-5` (negative handled by MINUS operator)

**Implementation**: The value is converted to an integer: `t.value = int(t.value)`

### 5.3 Strings

**Pattern**: `r'"[^"]*"'`

**Description**:
- Starts and ends with double quotes (`"`)
- Can contain any characters except unescaped double quotes
- Quotes are removed during tokenization

**Examples**:
- Valid: `"/data/financial"`, `"read"`, `"Hello World"`
- Invalid: `'single quotes'` (must use double quotes), `"unclosed` (missing closing quote)

**Implementation**: The quotes are stripped: `t.value = t.value[1:-1]`

**Future Enhancement**: Support for escape sequences like `\"`, `\n`, `\t` could be added.

## 6. Special Tokens

### 6.1 Newlines

**Pattern**: `r'\n+'`

**Description**: 
- Matches one or more newline characters
- Used to track line numbers for error reporting
- Not returned as a token (whitespace is ignored)

**Implementation**: Updates the lexer's line counter: `t.lexer.lineno += len(t.value)`

### 6.2 Ignored Characters

**Pattern**: `t_ignore = ' \t'`

**Description**:
- Spaces and tabs are ignored (not tokenized)
- Used for formatting and readability
- Does not affect parsing

**Future Enhancement**: Could add support for comments:
- Single-line: `// comment`
- Multi-line: `/* comment */`

## 7. Error Handling

**Function**: `def t_error(t)`

**Description**: 
- Called when an illegal character is encountered
- Prints error message with line number and column position
- Skips the illegal character and continues tokenization

**Example Error Output**:
```
Illegal character '@' at line 3, column 15
```

## 8. Complete Regex Reference Table

| Category | Token | Regex | Escaped? | Notes |
|----------|-------|-------|----------|-------|
| Keyword | `ROLE` | `ROLE` | No | Case-sensitive |
| Keyword | `USER` | `USER` | No | Case-sensitive |
| Keyword | `RESOURCE` | `RESOURCE` | No | Case-sensitive |
| Keyword | `ALLOW` | `ALLOW` | No | Case-sensitive |
| Keyword | `DENY` | `DENY` | No | Case-sensitive |
| Keyword | `IF` | `IF` | No | Case-sensitive |
| Keyword | `ON` | `ON` | No | Case-sensitive |
| Keyword | `AND` | `AND` | No | Case-sensitive |
| Keyword | `OR` | `OR` | No | Case-sensitive |
| Keyword | `CAN` | `[Cc][Aa][Nn]` | No | Case-insensitive |
| Keyword | `PATH` | `[Pp][Aa][Tt][Hh]` | No | Case-insensitive |
| Keyword | `ACTION` | `[Aa][Cc][Tt][Ii][Oo][Nn]` | No | Case-insensitive |
| Operator | `GE` | `>=` | No | Multi-char, before `>` |
| Operator | `LE` | `<=` | No | Multi-char, before `<` |
| Operator | `EQ` | `==` | No | Multi-char, before `=` |
| Operator | `NE` | `!=` | No | Multi-char |
| Operator | `PLUS` | `\+` | Yes | Escape `+` |
| Operator | `MINUS` | `-` | No | |
| Operator | `TIMES` | `\*` | Yes | Escape `*`, context-aware |
| Operator | `WILDCARD` | `\*` | Yes | Escape `*`, context-aware |
| Operator | `DIVIDE` | `/` | No | |
| Operator | `GT` | `>` | No | After multi-char |
| Operator | `LT` | `<` | No | After multi-char |
| Punctuation | `LBRACE` | `\{` | Yes | Escape `{` |
| Punctuation | `RBRACE` | `\}` | Yes | Escape `}` |
| Punctuation | `LPAREN` | `\(` | Yes | Escape `(` |
| Punctuation | `RPAREN` | `\)` | Yes | Escape `)` |
| Punctuation | `COLON` | `:` | No | |
| Punctuation | `DOT` | `\.` | Yes | Escape `.` |
| Punctuation | `COMMA` | `,` | No | |
| Literal | `IDENTIFIER` | `[a-zA-Z_][a-zA-Z0-9_]*` | No | Function-based |
| Literal | `NUMBER` | `\d+` | No | Function-based |
| Literal | `STRING` | `"[^"]*"` | No | Function-based |
| Special | Newline | `\n+` | No | Function-based |
| Special | Ignore | ` \t` | No | Variable-based |

## 9. Testing Examples

### Example 1: Role Definition
```
Input:  ROLE Admin {can: *}
Tokens: ROLE IDENTIFIER LBRACE CAN COLON WILDCARD RBRACE
Note: * is detected as WILDCARD (after colon, inside braces)
```

### Example 2: User Definition
```
Input:  USER JaneDoe {role: Developer}
Tokens: USER IDENTIFIER LBRACE IDENTIFIER COLON IDENTIFIER RBRACE
Note: 'role' is an IDENTIFIER (not a keyword)
```

### Example 3: Resource Definition
```
Input:  RESOURCE DB_Finance {path: "/data/financial"}
Tokens: RESOURCE IDENTIFIER LBRACE PATH COLON STRING RBRACE
```

### Example 4: Policy with Condition
```
Input:  ALLOW action: read ON resource: DB_Finance IF (time.hour > 9)
Tokens: ALLOW ACTION COLON IDENTIFIER ON IDENTIFIER COLON IDENTIFIER 
        IF LPAREN IDENTIFIER DOT IDENTIFIER GT NUMBER RPAREN
Note: 'action' is ACTION token, 'resource' is IDENTIFIER
```

### Example 5: Arithmetic Expression
```
Input:  3 + 4 * 10
Tokens: NUMBER PLUS NUMBER TIMES NUMBER
```

### Example 6: Boolean Expression
```
Input:  time.hour > 9 AND time.hour < 17
Tokens: IDENTIFIER DOT IDENTIFIER GT NUMBER AND IDENTIFIER DOT IDENTIFIER LT NUMBER
```

## 10. Common Regex Patterns Reference

| Pattern | Meaning | Example Matches |
|---------|---------|-----------------|
| `[a-zA-Z]` | Any letter (lowercase or uppercase) | `a`, `Z`, `M` |
| `[0-9]` or `\d` | Any digit | `0`, `5`, `9` |
| `[a-zA-Z0-9_]` | Alphanumeric or underscore | `a`, `5`, `_` |
| `[^"]` | Any character except double quote | `a`, `1`, ` ` |
| `+` | One or more of preceding | `\d+` matches `123` |
| `*` | Zero or more of preceding | `[a-z]*` matches `abc` or `` |
| `\` | Escape character | `\+` matches literal `+` |
| `^` | Start of string (in character class: negation) | `[^"]` means "not quote" |
| `$` | End of string | Not used in our patterns |

## 11. Implementation Notes

1. **Token Order**: Multi-character patterns must be defined before single-character patterns
2. **Keyword Recognition**: Keywords are checked in the `t_IDENTIFIER` function using a dictionary lookup. Attribute keywords (`CAN`, `PATH`, `ACTION`) support case-insensitive matching.
3. **Value Conversion**: Numbers are converted to integers, strings have quotes removed, attribute keywords are normalized to uppercase
4. **Line Tracking**: Newlines update the lexer's line counter for error reporting
5. **Error Recovery**: Illegal characters are skipped, allowing tokenization to continue
6. **Context-Aware Wildcard Detection**: The `t_TIMES` function examines surrounding characters to determine if `*` should be `WILDCARD` (permission context) or `TIMES` (arithmetic context). This happens during tokenization, not parsing.

## 12. Future Enhancements

- Support for floating-point numbers: `r'\d+\.\d+'`
- Support for negative numbers: Handle unary minus in parser
- Support for escape sequences in strings: `\"`, `\n`, `\t`, `\\`
- Support for comments: `// single-line` and `/* multi-line */`
- Support for different string delimiters: Single quotes `'...'`
- Support for character literals: `'a'`, `'\n'`

