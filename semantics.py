import sys
from parser import parser 
from symbol_table import SymbolTable

class SemanticAnalyzer:
    def __init__(self):
        self.symtab = SymbolTable()
        self.errors = []

    def log_error(self, message, line):
        self.errors.append(f"[Line {line}] SEMANTIC ERROR: {message}")
        print(f"[Line {line}] SEMANTIC ERROR: {message}")

    # --- MAIN WALKER ---
    def visit(self, node):
        if isinstance(node, tuple):
            tag = node[0]
            method_name = f'visit_{tag}'
            visitor = getattr(self, method_name, self.generic_visit)
            return visitor(node)
        elif isinstance(node, list):
            for item in node:
                self.visit(item)

    def generic_visit(self, node):
        # Fallback for nodes that don't need specific visiting
        pass 

    # --- VISITORS (With Error Reporting) ---

    def visit_PROGRAM(self, node):
        self.visit(node[1])

    def visit_ROLE_DEF(self, node):
        data = node[1]
        try:
            self.symtab.define_role(data['name'], data['scope'])
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_RESOURCE_DEF(self, node):
        data = node[1]
        try:
            self.symtab.define_resource(data['name'], data['path'])
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_USER_DEF(self, node):
        data = node[1]
        try:
            self.symtab.define_user(data['name'], data['role'])
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_POLICY_RULE(self, node):
        data = node[1]
        line = data['line']
        
        # 1. Check Binding (Resource Existence)
        try:
            self.symtab.add_policy(data)
        except ValueError as e:
            self.log_error(str(e), line)
            # Continue to analyze condition even if binding fails

        # 2. Check Scope & Types (Condition Validity)
        condition_type = self.analyze_expression(data['condition'], line)
        
        # 3. Ensure Condition is Boolean
        if condition_type and condition_type != 'bool':
            self.log_error(f"Policy condition must evaluate to 'bool', got '{condition_type}'", line)

    # --- EXPRESSION ANALYZER (Type Checking) ---
    def analyze_expression(self, node, line_num):
        if not isinstance(node, tuple):
            return None

        tag = node[0]

        if tag == 'BINARY_OP':
            op = node[1]
            left_type = self.analyze_expression(node[2], line_num)
            right_type = self.analyze_expression(node[3], line_num)

            if left_type is None or right_type is None:
                return None # Error already logged

            # Arithmetic Operations
            if op in ['+', '-', '*', '/']:
                if left_type == 'int' and right_type == 'int':
                    return 'int'
                else:
                    self.log_error(f"Operator '{op}' requires 'int' operands, got '{left_type}' and '{right_type}'", line_num)
                    return None
            
            # Relational Operations
            elif op in ['>', '<', '>=', '<=']:
                if left_type == right_type and left_type in ['int', 'float']: # Assuming only int for now
                    return 'bool'
                else:
                    self.log_error(f"Operator '{op}' requires comparable numeric operands, got '{left_type}' and '{right_type}'", line_num)
                    return None
            
            # Equality Operations
            elif op in ['==', '!=']:
                if left_type == right_type:
                    return 'bool'
                else:
                    self.log_error(f"Cannot compare different types '{left_type}' and '{right_type}'", line_num)
                    return None
            
            # Logical Operations
            elif op in ['AND', 'OR']:
                if left_type == 'bool' and right_type == 'bool':
                    return 'bool'
                else:
                    self.log_error(f"Logical operator '{op}' requires 'bool' operands, got '{left_type}' and '{right_type}'", line_num)
                    return None

        elif tag == 'UNARY_OP':
            op = node[1]
            operand_type = self.analyze_expression(node[2], line_num)
            if operand_type == 'int':
                return 'int'
            self.log_error(f"Unary operator '{op}' requires 'int', got '{operand_type}'", line_num)
            return None

        elif tag == 'ATTRIBUTE':
            obj = node[1]
            attr = node[2]
            attr_type = self.symtab.resolve_attribute(obj, attr)
            if attr_type:
                return attr_type
            else:
                self.log_error(f"Unknown or invalid attribute '{obj}.{attr}'", line_num)
                return None

        elif tag == 'VAR':
            var_name = node[1]
            # Simple variable resolution logic or error
            # For now, assuming only attributes are strongly typed in context
            # Could check symtab.resolve_variable if needed
            if self.symtab.resolve_variable(var_name):
                 # In a real compiler, we'd need to know the type of the variable.
                 # For this simplified SPL, maybe assume 'str' or 'int' based on usage?
                 # Or just return None/Error if we strictly want object.attribute syntax.
                 # Let's check context for top-level vars if any
                 return 'unknown' 
            self.log_error(f"Unknown variable '{var_name}'", line_num)
            return None

        elif tag == 'NUM':
            return 'int'

        elif tag == 'STR':
            return 'str'
            
        return None

    # --- RUNNER ---
    def run(self, source_code):
        print("\n=== SEMANTIC ANALYSIS START ===")
        self.errors = []
        # Re-initialize symbol table for clean run
        self.symtab = SymbolTable()
        
        ast = parser.parse(source_code)
        if ast:
            self.visit(ast)
            
        print("=== ANALYSIS COMPLETE ===\n")
        if self.errors:
            print(f"Found {len(self.errors)} semantic errors.")
        else:
            print("No semantic errors found.")
            print(self.symtab)

if __name__ == "__main__":
    analyzer = SemanticAnalyzer()
    
    # Test Data with Intentional Errors
    code = """
    ROLE Admin {can: *}
    RESOURCE DB_Finance {path: "/data/financial"}
    
    # Line 6: Valid User
    USER Jane { role: Admin }
    
    # Line 9: Error (Role 'Hacker' not defined)
    USER Bob { role: Hacker } 
    
    # Line 12: Type Error (weather.snow is int, comparing to string)
    ALLOW action: read ON resource: DB_Finance IF (weather.snow > "high")
    
    # Line 15: valid
    ALLOW action: write ON resource: DB_Finance IF (time.hour > 17 AND user.role == "intern")
    """
    
    print(f"Processing Code:\n{code}")
    analyzer.run(code)
