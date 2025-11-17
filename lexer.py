"""
Secure Policy Language (SPL) - Lexer
University of Technology, Jamaica - CIT4004
Analysis of Programming Languages Project

Team Members:
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

This module implements the lexical analyzer (tokenizer) for SPL.
It recognizes all tokens including keywords, operators, literals, and punctuation.
"""

import ply.lex as lex

# ============================================
# TOKEN DEFINITIONS
# ============================================
# Note: Order matters! Multi-character tokens must be defined before single-character ones.
tokens = (
    # Keywords (reserved words)
    'ROLE', 'USER', 'RESOURCE', 'ALLOW', 'DENY', 'IF', 'ON', 'AND', 'OR',
    'CAN', 'PATH', 'ACTION',
    
    # Comparison Operators (multi-character first)
    'EQ',      # ==
    'NE',      # !=
    'LE',      # <=
    'GE',      # >=
    
    # Arithmetic Operators
    'PLUS',    # +
    'MINUS',   # -
    'TIMES',   # * (multiplication)
    'DIVIDE',  # /
    
    # Wildcard (context-dependent *)
    'WILDCARD',  # * (wildcard in permissions)
    
    # Comparison Operators (single-character)
    'LT',      # <
    'GT',      # >
    
    # Literals
    'IDENTIFIER',  # Variable names, attribute names (can, role, path, action, resource)
    'NUMBER',      # Integer numbers
    'STRING',      # String literals
    
    # Punctuation and Delimiters
    'LBRACE',   # {
    'RBRACE',   # }
    'LPAREN',   # (
    'RPAREN',   # )
    'COLON',    # :
    'DOT',      # .
    'COMMA',    # ,
)

# Keywords dictionary - maps keyword strings to token types
# Note: 'can', 'role', 'path', 'action', 'resource' are attribute name keywords
# They are recognized as special tokens for stricter parsing
# Case-insensitive matching - both 'can' and 'CAN' map to 'CAN' token
keywords = {
    'ROLE': 'ROLE',
    'USER': 'USER',
    'RESOURCE': 'RESOURCE',
    'ALLOW': 'ALLOW',
    'DENY': 'DENY',
    'IF': 'IF',
    'ON': 'ON',
    'AND': 'AND',
    'OR': 'OR',
    'CAN': 'CAN',
    'PATH': 'PATH',
    'ACTION': 'ACTION',
    # Also add lowercase versions for case-insensitive matching in t_IDENTIFIER
    'can': 'CAN',
    'path': 'PATH',
    'action': 'ACTION',
}

# ============================================
# REGULAR EXPRESSIONS FOR TOKENS
# ============================================
# Note: PLY matches tokens in the order they appear in the file.
# Functions are matched in order of definition, so multi-character patterns
# should be defined before single-character patterns.

# Keywords (case-sensitive)
def t_ROLE(t):
    r'ROLE'
    return t

def t_USER(t):
    r'USER'
    return t

def t_RESOURCE(t):
    r'RESOURCE'
    return t

def t_ALLOW(t):
    r'ALLOW'
    return t

def t_DENY(t):
    r'DENY'
    return t

def t_IF(t):
    r'IF'
    return t

def t_ON(t):
    r'ON'
    return t

def t_AND(t):
    r'AND'
    return t

def t_OR(t):
    r'OR'
    return t

def t_CAN(t):
    r'[Cc][Aa][Nn]'  # Matches 'can' or 'CAN' (case-insensitive)
    # Normalize to uppercase for token type
    t.value = t.value.upper()
    return t

def t_PATH(t):
    r'[Pp][Aa][Tt][Hh]'  # Matches 'path' or 'PATH' (case-insensitive)
    # Normalize to uppercase for token type
    t.value = t.value.upper()
    return t

def t_ACTION(t):
    r'[Aa][Cc][Tt][Ii][Oo][Nn]'  # Matches 'action' or 'ACTION' (case-insensitive)
    # Normalize to uppercase for token type
    t.value = t.value.upper()
    return t

# Comparison Operators (multi-character - must come before single-character)
def t_GE(t):
    r'>='
    return t

def t_LE(t):
    r'<='
    return t

def t_EQ(t):
    r'=='
    return t

def t_NE(t):
    r'!='
    return t

# Arithmetic Operators
def t_PLUS(t):
    r'\+'
    return t

def t_MINUS(t):
    r'-'
    return t

def t_TIMES(t):
    r'\*'
    # Determine if * is wildcard or multiplication based on context
    # Look at surrounding characters to determine context
    
    # Get the position in the input string
    pos = t.lexer.lexpos
    data = t.lexer.lexdata
    
    # Check what comes before the *
    before_start = max(0, pos - 30)  # Look back up to 30 chars
    before_text = data[before_start:pos]
    
    # Check what comes after the *
    after_end = min(len(data), pos + 1 + 30)  # Look ahead up to 30 chars
    after_text = data[pos + 1:after_end]
    
    # Wildcard context: * appears after COLON (especially after attribute keywords)
    # Examples: {can: *}, action: *, {can: read, *}
    is_wildcard = False
    
    # Check if we're in an attribute context (after COLON)
    # Look for patterns like "can:", "action:", "path:" followed by whitespace and *
    before_stripped = before_text.strip()
    
    # Check if there's a colon before the *
    if ':' in before_stripped:
        # Find the last colon before this position
        last_colon_pos = before_stripped.rfind(':')
        if last_colon_pos >= 0:
            # Get text between colon and *
            between = before_stripped[last_colon_pos + 1:].strip()
            
            # If there's only whitespace between : and *, it's likely a wildcard
            if not between or between == '':
                # Check what comes after - should be }, ,, whitespace, or keyword (ON, IF, etc.)
                after_stripped = after_text.strip()
                if (after_stripped.startswith('}') or 
                    after_stripped.startswith(',') or 
                    not after_stripped or 
                    after_stripped[0].isspace() or
                    after_stripped.startswith('ON') or
                    after_stripped.startswith('IF') or
                    after_stripped.startswith('AND') or
                    after_stripped.startswith('OR')):
                    is_wildcard = True
    
    # Also check if we're inside braces { } which is a strong indicator of wildcard
    # Count braces before this position
    before_full = data[before_start:pos]
    open_braces = before_full.count('{')
    close_braces = before_full.count('}')
    if open_braces > close_braces:  # We're inside braces
        if ':' in before_stripped:  # And there's a colon nearby
            is_wildcard = True
    
    # Check for attribute keywords before colon (can, action, path)
    # This helps catch cases like "action: *" outside braces
    # Note: "action:" is tokenized as "ACTION COLON", so we need to check for the keyword
    if ':' in before_stripped:
        # Look for attribute keywords before the colon (case-insensitive)
        before_colon = before_stripped[:before_stripped.rfind(':')].strip().lower()
        # Check if it ends with can, action, or path (the actual words, not tokenized)
        if (before_colon.endswith('can') or 
            before_colon.endswith('action') or 
            before_colon.endswith('path') or
            before_colon.endswith('can ') or
            before_colon.endswith('action ') or
            before_colon.endswith('path ')):
            # Check if there's only whitespace between colon and *
            between = before_stripped[before_stripped.rfind(':') + 1:].strip()
            if not between or between == '':
                is_wildcard = True
    
    # Also check if we see "ON", "IF", "AND", "OR" after the * - this indicates wildcard context
    # in policy definitions like "action: * ON resource: ..."
    after_stripped = after_text.strip()
    if after_stripped.startswith('ON') or after_stripped.startswith('IF'):
        # If we're after a colon with attribute keyword, it's wildcard
        if ':' in before_stripped:
            before_colon = before_stripped[:before_stripped.rfind(':')].strip().lower()
            if (before_colon.endswith('can') or 
                before_colon.endswith('action') or 
                before_colon.endswith('path')):
                is_wildcard = True
    
    # Multiplication context: * appears between numbers or identifiers
    # Examples: 3 * 4, time.hour * 2, (a * b)
    is_multiplication = False
    if not is_wildcard:
        # Check if there's a number or identifier before
        before_clean = before_stripped.replace(' ', '').replace('\t', '').replace('\n', '')
        after_clean = after_text.strip().replace(' ', '').replace('\t', '').replace('\n', '')
        
        # If we have something like "number *" or "identifier *" followed by number/identifier
        if (before_clean and (before_clean[-1].isdigit() or before_clean[-1].isalpha() or before_clean[-1] == ')')) and \
           (after_clean and (after_clean[0].isdigit() or after_clean[0].isalpha() or after_clean[0] == '(')):
            is_multiplication = True
        # Also check if we're in an arithmetic expression context
        elif before_clean and (before_clean[-1].isdigit() or before_clean[-1].isalpha() or before_clean[-1] == ')'):
            # If followed by number, identifier, or operator, it's multiplication
            if after_clean and (after_clean[0].isdigit() or after_clean[0].isalpha() or after_clean[0] == '('):
                is_multiplication = True
    
    # Default to multiplication if context is unclear (safer for arithmetic)
    if is_wildcard:
        t.type = 'WILDCARD'
    else:
        t.type = 'TIMES'
    
    return t

def t_DIVIDE(t):
    r'/'
    return t

# Comparison Operators (single-character)
def t_GT(t):
    r'>'
    return t

def t_LT(t):
    r'<'
    return t

# Punctuation and Delimiters
def t_LBRACE(t):
    r'\{'
    return t

def t_RBRACE(t):
    r'\}'
    return t

def t_LPAREN(t):
    r'\('
    return t

def t_RPAREN(t):
    r'\)'
    return t

def t_COLON(t):
    r':'
    return t

def t_DOT(t):
    r'\.'
    return t

def t_COMMA(t):
    r','
    return t

# Literals
def t_STRING(t):
    r'"[^"]*"'
    # Remove quotes from string value
    t.value = t.value[1:-1]
    return t

def t_NUMBER(t):
    r'\d+'
    # Convert string to integer
    t.value = int(t.value)
    return t

def t_IDENTIFIER(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    # Check if identifier is a keyword
    # Keywords are case-sensitive and must match exactly
    t.type = keywords.get(t.value, 'IDENTIFIER')
    return t

# Special token definitions
def t_newline(t):
    r'\n+'
    # Track line numbers for error reporting
    t.lexer.lineno += len(t.value)

# Ignored characters (whitespace and tabs)
t_ignore = ' \t'

# Error handling
def t_error(t):
    """
    Handle illegal characters.
    Prints error message and skips the character.
    """
    print(f"Illegal character '{t.value[0]}' at line {t.lineno}, column {t.lexpos}")
    t.lexer.skip(1)

# ============================================
# BUILD THE LEXER
# ============================================
lexer = lex.lex()

# ============================================
# TESTING
# ============================================
if __name__ == "__main__":
    # Test with sample SPL code
    test_code = '''
    ROLE Admin {can: *}
    USER JaneDoe {role: Developer}
    RESOURCE DB_Finance {path: "/data/financial"}
    ALLOW action: read, write ON resource: DB_Finance
    IF (time.hour > 9 AND time.hour < 17)
    '''
    
    print("Testing SPL Lexer")
    print("=" * 50)
    lexer.input(test_code)
    
    for tok in lexer:
        print(f"Token: {tok.type:15} Value: {tok.value:20} Line: {tok.lineno}")
    
    print("\n" + "=" * 50)
    print("Interactive mode - Enter SPL code (or 'quit' to exit):")
    
    while True:
        try:
            data = input("\nSPL> ")
            if data.lower() in ['quit', 'exit', 'q']:
                break
            if not data.strip():
                continue
                
            lexer.input(data)
            for tok in lexer:
                print(f"  {tok.type:15} = {tok.value}")
        except EOFError:
            break
        except Exception as e:
            print(f"Error: {e}")