import ply.lex as lex

# Lexer states for handling multi-line comments
states = (
    ('comment', 'exclusive'),
)

# --- 1. RESERVED WORDS ---
# Mapping reserved words to token types ensures that 'IF' is seen as a keyword, 
# while 'iframe' would be seen as an identifier (ID).
reserved = {
    'ROLE': 'ROLE',
    'USER': 'USER',
    'RESOURCE': 'RESOURCE',
    'ALLOW': 'ALLOW',
    'DENY': 'DENY',
    'IF': 'IF',
    'THEN': 'THEN',
    'ELSE': 'ELSE',
    'AND': 'AND',
    'OR': 'OR',
    'NOT': 'NOT',
    'ON': 'ON',
    'CONST': 'CONST',
    'CALL': 'CALL',
    'POLICY': 'POLICY',
    # From example: {can: *}
    'can': 'CAN', 
    'action': 'ACTION',
    'resource': 'RESOURCE_KEY', # To distinguish from the top-level RESOURCE definition
    'role': 'ROLE_KEY',         # To distinguish from top-level ROLE
    'path': 'PATH_KEY'
}

# --- 2. TOKEN LIST ---
tokens = [
    'ID',
    'NUMBER',
    'STRING',
    'PLUS',
    'MINUS',
    'TIMES',    # Serves as multiplication (*) and wildcard (*) 
    'DIVIDE',   # Serves as division (/) and path separator (/)
    'LPAREN',
    'RPAREN',
    'LBRACE',   # {
    'RBRACE',   # }
    'LBRACKET', # [
    'RBRACKET', # ]
    'COMMA',
    'COLON',    # :
    'DOT',      # . (For object attributes like time.hour) 
    'GT',       # >
    'LT',       # <
    'GE',       # >=
    'LE',       # <=
    'EQ',       # ==
    'NE',       # !=
    'ASSIGN',   # = (for CONST assignments)
] + list(reserved.values())

# --- 3. REGEX RULES ---

# Arithmetic Operators 
t_PLUS    = r'\+'
t_MINUS   = r'-'
t_TIMES   = r'\*'  # Matches * for math AND * for wildcards
# Note: DIVIDE must come before COMMENT_MULTILINE to avoid matching /* as division
t_DIVIDE  = r'/'   # Matches / for math AND / for file paths

# Comparison Operators (for Boolean logic) [cite: 16]
t_GT      = r'>'
t_LT      = r'<'
t_GE      = r'>='
t_LE      = r'<='
t_EQ      = r'=='
t_NE      = r'!='
t_ASSIGN  = r'='

# Delimiters
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_LBRACE  = r'\{'
t_RBRACE  = r'\}'
t_LBRACKET = r'\['
t_RBRACKET = r'\]'
t_COMMA   = r','
t_COLON   = r':'
t_DOT     = r'\.'

# Identifiers and Reserved Words
def t_ID(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    # Check if this ID is actually a reserved keyword
    t.type = reserved.get(t.value, 'ID') 
    return t

# Numbers
def t_NUMBER(t):
    r'\d+'
    t.value = int(t.value)
    return t

# Strings (Double quoted)
# Useful for paths if the user quotes them: "data/financial"
def t_STRING(t):
    r'\"([^\\\n]|(\\.))*?\"'
    t.value = t.value[1:-1] # Remove the quotes
    return t

# Track line numbers (Crucial for error reporting requirements )
# Handle both Unix (\n) and Windows (\r\n) line endings
def t_newline(t):
    r'(\r?\n)+'
    # Count actual newlines (handle \r\n as single line)
    t.lexer.lineno += t.value.count('\n')

# Ignore spaces, tabs, and carriage returns
t_ignore  = ' \t\r'

# Comments - Single-line (// style)
def t_ignore_COMMENT_SLASH(t):
    r'//.*'
    pass

# Comments - Multi-line (/* ... */)
# Enter comment state
def t_COMMENT_MULTILINE_START(t):
    r'/\*'
    t.lexer.begin('comment')
    pass

# In comment state - ignore spaces, tabs, and carriage returns
t_comment_ignore = ' \t\r'

# In comment state - handle content (with Windows line ending support)
def t_comment_newline(t):
    r'(\r?\n)+'
    t.lexer.lineno += t.value.count('\n')

def t_comment_content(t):
    r'[^*/\n]+'
    pass

def t_comment_end(t):
    r'\*/'
    t.lexer.begin('INITIAL')
    pass

def t_comment_star(t):
    r'\*'
    pass

def t_comment_slash(t):
    r'/'
    pass

# Error handling in comment state
def t_comment_error(t):
    t.lexer.skip(1)

# Error handling
def t_error(t):
    print(f"Illegal character '{t.value[0]}' at line {t.lexer.lineno}")
    t.lexer.skip(1)

# Build the lexer
lexer = lex.lex()

# --- TEST HARNESS ---
# Only runs if you execute this file directly (python lexer.py)
if __name__ == "__main__":
    print("SPL Lexer (type 'quit' to exit)")
    while True:
        try:
            data = input('SPL > ')
            if data.lower() == 'quit': break
            lexer.input(data)
            for tok in lexer:
                print(tok)
        except EOFError:
            break