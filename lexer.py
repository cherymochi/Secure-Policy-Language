import ply.lex as lex

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
    'TO': 'TO',
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
    'COMMA',
    'COLON',    # :
    'DOT',      # . (For object attributes like time.hour) 
    'GT',       # >
    'LT',       # <
    'GE',       # >=
    'LE',       # <=
    'EQ',       # ==
    'NE',       # !=
] + list(reserved.values())

# --- 3. REGEX RULES ---

# Arithmetic Operators 
t_PLUS    = r'\+'
t_MINUS   = r'-'
t_TIMES   = r'\*'  # Matches * for math AND * for wildcards
t_DIVIDE  = r'/'   # Matches / for math AND / for file paths

# Comparison Operators (for Boolean logic) [cite: 16]
t_GT      = r'>'
t_LT      = r'<'
t_GE      = r'>='
t_LE      = r'<='
t_EQ      = r'=='
t_NE      = r'!='

# Delimiters
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_LBRACE  = r'\{'
t_RBRACE  = r'\}'
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
def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

# Ignore spaces and tabs
t_ignore  = ' \t'

# Comments (Standard # style)
def t_ignore_COMMENT(t):
    r'\#.*'
    pass

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