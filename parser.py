import ply.yacc as yacc
import pprint
from lexer import tokens

# --- PRECEDENCE ---
precedence = (
    ('left', 'OR'),
    ('left', 'AND'),
    ('right', 'NOT'),
    ('nonassoc', 'EQ', 'NE', 'GT', 'LT', 'GE', 'LE'),
    ('left', 'PLUS', 'MINUS'),
    ('left', 'TIMES', 'DIVIDE'),
    ('right', 'UMINUS'),
)

# --- GRAMMAR RULES ---

def p_program(p):
    'program : statements'
    p[0] = ('PROGRAM', p[1])

def p_statements_multiple(p):
    'statements : statement statements'
    p[0] = [p[1]] + p[2]

def p_statements_single(p):
    'statements : statement'
    p[0] = [p[1]]

def p_statement(p):
    '''statement : role_def
                 | user_def
                 | resource_def
                 | rule_def'''
    p[0] = p[1]

# --- DEFINITIONS (Capturing Line Numbers) ---

def p_role_def(p):
    'role_def : ROLE ID LBRACE CAN COLON TIMES RBRACE'
    # Store p.lineno(1) to know where "ROLE" was typed
    p[0] = ('ROLE_DEF', {'name': p[2], 'scope': 'ALL', 'line': p.lineno(1)})

def p_user_def(p):
    'user_def : USER ID LBRACE ROLE_KEY COLON ID RBRACE'
    p[0] = ('USER_DEF', {'name': p[2], 'role': p[6], 'line': p.lineno(1)})

def p_resource_def(p):
    'resource_def : RESOURCE ID LBRACE PATH_KEY COLON path_expr RBRACE'
    p[0] = ('RESOURCE_DEF', {'name': p[2], 'path': p[6], 'line': p.lineno(1)})

def p_rule_def(p):
    '''rule_def : ALLOW action_clause ON resource_clause IF expression
                | DENY action_clause ON resource_clause IF expression'''
    p[0] = ('POLICY_RULE', {
        'type': p[1],
        'actions': p[2],
        'resource': p[4],
        'condition': p[6],
        'line': p.lineno(1)
    })

# --- HELPERS ---
def p_action_clause(p):
    'action_clause : ACTION COLON id_list'
    p[0] = p[3]

def p_resource_clause(p):
    'resource_clause : RESOURCE_KEY COLON ID'
    p[0] = p[3]

def p_id_list_multi(p):
    'id_list : ID COMMA id_list'
    p[0] = [p[1]] + p[3]

def p_id_list_single(p):
    'id_list : ID'
    p[0] = [p[1]]

# --- EXPRESSIONS ---
def p_expression_binop(p):
    '''expression : expression PLUS expression
                  | expression MINUS expression
                  | expression TIMES expression
                  | expression DIVIDE expression
                  | expression AND expression
                  | expression OR expression
                  | expression GT expression
                  | expression LT expression
                  | expression GE expression
                  | expression LE expression
                  | expression EQ expression
                  | expression NE expression'''
    p[0] = ('BINARY_OP', p[2], p[1], p[3])

def p_expression_uminus(p):
    'expression : MINUS expression %prec UMINUS'
    p[0] = ('UNARY_OP', '-', p[2])

def p_expression_group(p):
    'expression : LPAREN expression RPAREN'
    p[0] = p[2]

def p_expression_num(p):
    'expression : NUMBER'
    p[0] = ('NUM', p[1])

def p_expression_str(p):
    'expression : STRING'
    p[0] = ('STR', p[1])

def p_expression_id(p):
    'expression : ID'
    p[0] = ('VAR', p[1])

def p_expression_attr(p):
    '''expression : ID DOT ID
                  | ID DOT ROLE_KEY
                  | ID DOT RESOURCE_KEY
                  | ID DOT ACTION
                  | ID DOT CAN
                  | ID DOT PATH_KEY'''
    p[0] = ('ATTRIBUTE', p[1], p[3])

def p_path_expr(p):
    'path_expr : STRING'
    p[0] = p[1]

# --- ERROR HANDLING ---
def p_error(p):
    if p:
        print(f"(!) SYNTAX ERROR: Unexpected token '{p.value}' at line {p.lineno}")
        parser.errok()
    else:
        print("(!) SYNTAX ERROR: Unexpected end of file")

parser = yacc.yacc()

if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=2)
    # [cite_start]Test Data from Project PDF [cite: 1]
    code = """
    ROLE Admin {can: *}
    RESOURCE DB_Finance {path: "/data/financial"}
    USER Jane { role: Admin }
    ALLOW action: read, write ON resource: DB_Finance IF (time.hour > 9)
    """
    print("--- SPL Parser Test ---")
    result = parser.parse(code)
    pp.pprint(result)