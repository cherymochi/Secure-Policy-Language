import sys
from parser import parser 
from symbol_table import SymbolTable
from security_rules import SecurityScanner

class SemanticAnalyzer:
    def __init__(self):
        self.symtab = SymbolTable()
        self.errors = []
        self.security_risks = []

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
            # Handle both old format (path only) and new format (attributes dict)
            if 'attributes' in data:
                self.symtab.define_resource(data['name'], data['attributes'])
            elif 'path' in data:
                # Backward compatibility: old format with just path
                self.symtab.define_resource(data['name'], data['path'])
            else:
                self.log_error("Resource definition missing 'path' attribute", data['line'])
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_CONST_DEF(self, node):
        data = node[1]
        try:
            self.symtab.define_constant(data['name'], data['value'])
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_CALL_DEF(self, node):
        data = node[1]
        call_type = data['type']
        name = data.get('name')
        
        try:
            if call_type == 'ROLE':
                if name:
                    result = self.symtab.query_role(name)
                    if result:
                        print(f"[CALL ROLE {name}] {result}")
                    else:
                        self.log_error(f"Role '{name}' not found", data['line'])
                else:
                    results = self.symtab.query_roles()
                    if results:
                        print(f"[CALL ROLE] Found {len(results)} role(s):")
                        for r in results:
                            print(f"[CALL ROLE] {r}")
                    else:
                        print("[CALL ROLE] No roles defined")
            elif call_type == 'RESOURCE':
                if name:
                    result = self.symtab.query_resource(name)
                    if result:
                        print(f"[CALL RESOURCE {name}] {result}")
                    else:
                        self.log_error(f"Resource '{name}' not found", data['line'])
                else:
                    results = self.symtab.query_resources()
                    if results:
                        print(f"[CALL RESOURCE] Found {len(results)} resource(s):")
                        for r in results:
                            print(f"[CALL RESOURCE] {r}")
                    else:
                        print("[CALL RESOURCE] No resources defined")
            elif call_type == 'USER':
                if name:
                    result = self.symtab.query_user(name)
                    if result:
                        print(f"[CALL USER {name}] {result}")
                    else:
                        self.log_error(f"User '{name}' not found", data['line'])
                else:
                    results = self.symtab.query_users()
                    if results:
                        print(f"[CALL USER] Found {len(results)} user(s):")
                        for r in results:
                            print(f"[CALL USER] {r}")
                    else:
                        print("[CALL USER] No users defined")
            elif call_type == 'CONST':
                if name:
                    result = self.symtab.query_constant(name)
                    if result:
                        print(f"[CALL CONST {name}] {result}")
                    else:
                        self.log_error(f"Constant '{name}' not found", data['line'])
                else:
                    results = self.symtab.query_constants()
                    if results:
                        print(f"[CALL CONST] Found {len(results)} constant(s):")
                        for r in results:
                            print(f"[CALL CONST] {r}")
                    else:
                        print("[CALL CONST] No constants defined")
            elif call_type == 'POLICY':
                if name:
                    result = self.symtab.query_policy(name)
                    if result:
                        print(f"[CALL POLICY {name}]")
                        for line in result.split('\n'):
                            print(f"[CALL POLICY {name}] {line}")
                    else:
                        self.log_error(f"Policy '{name}' not found", data['line'])
                else:
                    results = self.symtab.query_policies()
                    if results:
                        print(f"[CALL POLICY] Found {len(results)} policy/policies:")
                        for r in results:
                            print(f"[CALL POLICY] {r}")
                    else:
                        print("[CALL POLICY] No policies defined")
            else:
                self.log_error(f"Unknown CALL type: {call_type}", data['line'])
        except Exception as e:
            self.log_error(f"CALL error: {str(e)}", data['line'])

    def visit_USER_DEF(self, node):
        data = node[1]
        try:
            # Handle both old format (single role) and new format (multiple roles)
            roles = data.get('roles', data.get('role'))
            if roles is None:
                self.log_error("User definition missing role(s)", data['line'])
            else:
                # define_user will validate roles using lookup (checks current and parent scopes)
                self.symtab.define_user(data['name'], roles)
        except ValueError as e:
            self.log_error(str(e), data['line'])

    def visit_POLICY_DEF(self, node):
        data = node[1]
        policy_name = data['name']
        body = data['body']  # Changed from 'rules' to 'body' - can contain any statements
        
        try:
            # Enter POLICY scope
            self.symtab.enter_scope(f"POLICY_{policy_name}")
            
            # Process all statements in the policy body
            for stmt in body:
                self.visit(stmt)
            
            # Store the policy definition (with full body)
            self.symtab.define_policy(policy_name, body)
            
            # Exit POLICY scope
            self.symtab.exit_scope()
        except ValueError as e:
            self.log_error(str(e), data['line'])
            # Make sure we exit scope even on error
            if len(self.symtab.scope_stack) > 1:
                self.symtab.exit_scope()

    def visit_POLICY_RULE(self, node):
        data = node[1]
        line = data['line']
        
        # Only add to policies list if it's a standalone rule (not inside a POLICY block)
        # Policy blocks are handled by visit_POLICY_DEF
        # Check if we're inside a policy definition by checking the parent context
        # For now, we'll add it and let POLICY_DEF handle the grouping
        
        # 1. Check Binding (Resource Existence)
        try:
            self.symtab.add_policy(data)
        except ValueError as e:
            self.log_error(str(e), line)
            # Continue to analyze condition even if binding fails

        # 2. Check Scope & Types (Condition Validity)
        condition_type = self.analyze_expression(data.get('condition'), line)
        
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
            if attr_type is not None:
                return attr_type  # Returns the actual type (e.g., 'int', 'str')
            else:
                self.log_error(f"Unknown or invalid attribute '{obj}.{attr}'", line_num)
                return None

        elif tag == 'VAR':
            var_name = node[1]
            # Check if it's a constant (using lookup which checks current and parent scopes)
            const_value = self.symtab.lookup_constant(var_name)
            if const_value is not None:
                # Determine type based on value
                if isinstance(const_value, int):
                    return 'int'
                elif isinstance(const_value, str):
                    return 'str'
                else:
                    return 'unknown'
            # Check if it's in context
            if self.symtab.resolve_variable(var_name):
                return 'unknown'  # Context variables
            self.log_error(f"Unknown variable or constant '{var_name}'", line_num)
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
            
            # --- SECURITY SCAN ---
            print("\n=== SECURITY SCAN START ===")
            scanner = SecurityScanner(self.symtab)
            self.security_risks = scanner.scan()
            
            if self.security_risks:
                print(f"Found {len(self.security_risks)} potential security risks:")
                for risk in self.security_risks:
                    print(f"  [{risk['level']}] Line {risk['line']}: {risk['message']}")
            else:
                print("No security risks found.")
            print("=== SECURITY SCAN COMPLETE ===")

if __name__ == "__main__":
    analyzer = SemanticAnalyzer()
    
    # Test Data with Intentional Risks (but valid syntax)
    code = """
    ROLE Admin {can: *}
    RESOURCE DB_Finance {path: "/data/financial"}
    
    # Line 6: Valid User
    USER Jane { role: Admin }
    
    # Line 9: Overly permissive rule
    ALLOW action: * ON resource: DB_Finance IF (time.hour > 9)
    
    # Line 12: Conflicting rule 1
    ALLOW action: write ON resource: DB_Finance IF (time.hour > 17)
    
    # Line 15: Conflicting rule 2
    DENY action: write ON resource: DB_Finance IF (time.hour < 5)
    """
    
    print(f"Processing Code:\n{code}")
    analyzer.run(code)
