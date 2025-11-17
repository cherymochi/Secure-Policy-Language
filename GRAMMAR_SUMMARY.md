# SPL Grammar, Tokens, and Regex - Summary

**Team Members:**
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

**University of Technology, Jamaica - CIT4004**

This document provides a quick reference for the completed grammar design, token definitions, and regex patterns for the Secure Policy Language (SPL).

## Files Created

1. **`grammar.ebnf`** - Complete EBNF grammar specification
2. **`tokens.md`** - Complete token list with descriptions
3. **`regex_patterns.md`** - Detailed regex pattern documentation
4. **`lexer.py`** - Updated lexer implementation with all tokens and regex patterns

## Quick Reference

### Grammar Format
- **Format**: EBNF (Extended Backus-Naur Form)
- **File**: `grammar.ebnf`
- **Status**: Complete

### Token Count
- **Keywords**: 12 (ROLE, USER, RESOURCE, ALLOW, DENY, IF, ON, AND, OR, CAN, PATH, ACTION)
- **Operators**: 11 (Arithmetic: 4, Comparison: 6, Wildcard: 1)
- **Punctuation**: 7 (Braces, Parentheses, Colon, Dot, Comma)
- **Literals**: 3 (IDENTIFIER, NUMBER, STRING)
- **Total**: 33 unique token types

### Key Features

✅ **Complete EBNF Grammar** - All language constructs defined
✅ **All Tokens Defined** - Keywords, operators, literals, punctuation
✅ **Regex Patterns** - All tokens have proper regex patterns
✅ **Token Priority** - Multi-character before single-character
✅ **Keyword Recognition** - Proper keyword vs identifier handling
✅ **Context-Aware Detection** - Automatically distinguishes WILDCARD vs TIMES for `*` symbol
✅ **Error Handling** - Illegal character detection
✅ **Line Tracking** - Line numbers for error reporting
✅ **Tested** - Lexer successfully tokenizes sample SPL code with context-aware wildcard detection

## Next Steps (Week 1, Day 3-4)

Now that the grammar, tokens, and regex are complete, the next tasks are:

1. ✅ **Complete** - Design complete grammar (EBNF format)
2. ✅ **Complete** - Define all tokens
3. ✅ **Complete** - Write regex patterns
4. ⏭️ **Next** - Implement parser.py with complete grammar rules
5. ⏭️ **Next** - Generate AST from parser
6. ⏭️ **Next** - Implement basic semantic.py

## Testing

The lexer has been tested with sample SPL code:
```spl
ROLE Admin {can: *}
USER JaneDoe {role: Developer}
RESOURCE DB_Finance {path: "/data/financial"}
ALLOW action: read, write ON resource: DB_Finance
IF (time.hour > 9 AND time.hour < 17)
```

All tokens are correctly recognized and tokenized.

## Documentation for Report

For your project report, you can reference:
- **Grammar**: `grammar.ebnf` (10 marks)
- **Token List**: `tokens.md` (5 marks)
- **Regular Expressions**: `regex_patterns.md` (10 marks)

All documentation is ready for inclusion in your project report.

