# symbol_table.py

class Scope:
    """Represents a scope (global or POLICY scope)"""
    def __init__(self, name="global", parent=None):
        self.name = name
        self.parent = parent  # Reference to parent scope (for nested scopes)
        self.roles = {}
        self.users = {}
        self.resources = {}
        self.constants = {}
        self.policies = []  # Standalone policy rules in this scope

class SymbolTable:
    def __init__(self):
        # --- 1. SCOPE MANAGEMENT ---
        self.global_scope = Scope("global")
        self.scope_stack = [self.global_scope]  # Stack of active scopes
        self.current_scope = self.global_scope
        
        # --- 2. NAMED POLICIES (stored globally, but can contain scoped definitions) ---
        self.named_policies = {}  # Stores policy_name -> policy definition node
        
        # --- 3. SCOPE CONTEXT (With Types) ---
        # Defines valid attributes and their expected types.
        # Matches requirement: "syntax... focused on attributes" 
        self.context = {
            'time':  {
                'hour': 'int', 
                'minute': 'int', 
                'day': 'str',      # Day of week: "Monday", "Tuesday", etc.
                'month': 'int',    # Month: 1-12
                'year': 'int'      # Year: e.g., 2025
            },
            'user':  {
                'role': 'str', 
                'id': 'int', 
                'department': 'str', 
                'ip': 'str'
            },
            'resource': {
                'tag': 'str', 
                'owner': 'str', 
                'size': 'int'
            },
            'weather': {
                'temp': 'int',
                'snow': 'int'
            } 
        }

    # --- SCOPE MANAGEMENT METHODS ---
    
    def enter_scope(self, name):
        """Enter a new scope (e.g., when entering a POLICY block)"""
        new_scope = Scope(name, parent=self.current_scope)
        self.scope_stack.append(new_scope)
        self.current_scope = new_scope
        print(f"[SymbolTable] Entered scope: {name}")
    
    def exit_scope(self):
        """Exit current scope (e.g., when leaving a POLICY block)"""
        if len(self.scope_stack) > 1:
            self.scope_stack.pop()
            self.current_scope = self.scope_stack[-1]
            print(f"[SymbolTable] Exited scope, returned to: {self.current_scope.name}")
        else:
            print("[SymbolTable] Warning: Attempted to exit global scope")
    
    def lookup_role(self, name):
        """Look up a role in current scope and parent scopes"""
        scope = self.current_scope
        while scope:
            if name in scope.roles:
                return scope.roles[name]
            scope = scope.parent
        return None
    
    def lookup_user(self, name):
        """Look up a user in current scope and parent scopes"""
        scope = self.current_scope
        while scope:
            if name in scope.users:
                return scope.users[name]
            scope = scope.parent
        return None
    
    def lookup_resource(self, name):
        """Look up a resource in current scope and parent scopes"""
        scope = self.current_scope
        while scope:
            if name in scope.resources:
                return scope.resources[name]
            scope = scope.parent
        return None
    
    def lookup_constant(self, name):
        """Look up a constant in current scope and parent scopes"""
        scope = self.current_scope
        while scope:
            if name in scope.constants:
                return scope.constants[name]
            scope = scope.parent
        return None

    # --- DEFINITION METHODS ---

    def define_role(self, name, scope):
        """Stores a role definition in the current scope."""
        if name in self.current_scope.roles:
            raise ValueError(f"Error: Role '{name}' is already defined in {self.current_scope.name} scope.")
        self.current_scope.roles[name] = scope
        print(f"[SymbolTable] Role defined in {self.current_scope.name} scope: {name}")

    def define_resource(self, name, attributes):
        """
        Stores a resource definition with attributes in the current scope.
        
        Args:
            name: Resource name
            attributes: Dictionary of attributes (e.g., {'path': '/data/financial', 'owner': 'Finance', ...})
                       For backward compatibility, can also accept a string (path) which will be converted
        """
        if name in self.current_scope.resources:
            raise ValueError(f"Error: Resource '{name}' is already defined in {self.current_scope.name} scope.")
        
        # Backward compatibility: if attributes is a string, treat it as path
        if isinstance(attributes, str):
            attributes = {'path': attributes}
        
        # Ensure path is always present (required attribute)
        if 'path' not in attributes:
            raise ValueError(f"Error: Resource '{name}' must have a 'path' attribute.")
        
        self.current_scope.resources[name] = attributes
        attrs_str = ', '.join(f"{k}: {v}" for k, v in attributes.items())
        print(f"[SymbolTable] Resource defined in {self.current_scope.name} scope: {name} ({attrs_str})")

    def define_user(self, name, roles):
        """
        Binds a user to one or more roles in the current scope.
        Performs Semantic Check: Do all roles exist?
        
        Args:
            name: User name
            roles: Single role name (str) or list of role names
        """
        if name in self.current_scope.users:
            raise ValueError(f"Error: User '{name}' is already defined in {self.current_scope.name} scope.")

        # Normalize to list
        if isinstance(roles, str):
            roles = [roles]
        
        # Validate all roles exist (check in current scope and parent scopes)
        for role_name in roles:
            if not self.lookup_role(role_name):
                raise ValueError(f"Error: Cannot assign undefined role '{role_name}' to user '{name}'.")
        
        self.current_scope.users[name] = roles
        roles_str = ', '.join(roles)
        print(f"[SymbolTable] User defined in {self.current_scope.name} scope: {name} (roles: {roles_str})")

    def define_constant(self, name, value):
        """Defines a constant in the current scope."""
        if name in self.current_scope.constants:
            raise ValueError(f"Error: Constant '{name}' is already defined in {self.current_scope.name} scope.")
        self.current_scope.constants[name] = value
        print(f"[SymbolTable] Constant defined in {self.current_scope.name} scope: {name} = {value}")

    def get_constant(self, name):
        """Gets the value of a constant (looks up in current and parent scopes)."""
        return self.lookup_constant(name)

    def define_policy(self, name, body):
        """
        Defines a named policy with a body of statements.
        
        Args:
            name: Policy name
            body: List of statement nodes (can include any statement type)
        """
        if name in self.named_policies:
            raise ValueError(f"Error: Policy '{name}' is already defined.")
        
        self.named_policies[name] = body
        print(f"[SymbolTable] Policy '{name}' defined")

    def add_policy(self, policy_node):
        """
        Stores a policy rule in the current scope.
        Performs Semantic Check: Does the resource exist?
        """
        resource_name = policy_node['resource']
        if not self.lookup_resource(resource_name):
            raise ValueError(f"Error: Policy refers to undefined resource '{resource_name}'.")
        
        self.current_scope.policies.append(policy_node)
        print(f"[SymbolTable] Policy added in {self.current_scope.name} scope for resource: {resource_name}")

    # --- SCOPE RESOLUTION METHODS ---

    def resolve_variable(self, var_name):
        """
        Resolves a variable name.
        First checks constants in current and parent scopes, then context.
        Returns True if variable exists, False otherwise.
        """
        if self.lookup_constant(var_name) is not None:
            return True
        if var_name in self.context:
            return True
        return False

    def resolve_attribute(self, obj, attr):
        """
        Resolves an attribute access (e.g., time.hour).
        Returns the type of the attribute if it exists, None otherwise.
        """
        if obj not in self.context:
            return None
        if attr not in self.context[obj]:
            return None
        return self.context[obj][attr]  # Return the actual type (e.g., 'int', 'str')

    # --- QUERY METHODS (for CALL statements) ---
    
    def query_roles(self):
        """Returns all roles from current scope and parent scopes."""
        result = []
        seen = set()
        scope = self.current_scope
        while scope:
            for name, scope_val in scope.roles.items():
                if name not in seen:
                    result.append(f"ROLE {name} {{can: {scope_val}}}")
                    seen.add(name)
            scope = scope.parent
        return result
    
    def query_role(self, name):
        """Returns information about a specific role."""
        role_scope = self.lookup_role(name)
        if role_scope is None:
            return None
        return f"ROLE {name} {{can: {role_scope}}}"
    
    def query_resources(self):
        """Returns all resources from current scope and parent scopes."""
        result = []
        seen = set()
        scope = self.current_scope
        while scope:
            for name, attrs in scope.resources.items():
                if name not in seen:
                    attrs_str = ', '.join(f"{k}: {v}" for k, v in attrs.items())
                    result.append(f"RESOURCE {name} {{{attrs_str}}}")
                    seen.add(name)
            scope = scope.parent
        return result
    
    def query_resource(self, name):
        """Returns information about a specific resource."""
        attrs = self.lookup_resource(name)
        if attrs is None:
            return None
        attrs_str = ', '.join(f"{k}: {v}" for k, v in attrs.items())
        return f"RESOURCE {name} {{{attrs_str}}}"
    
    def query_users(self):
        """Returns all users from current scope and parent scopes."""
        result = []
        seen = set()
        scope = self.current_scope
        while scope:
            for name, roles in scope.users.items():
                if name not in seen:
                    roles_str = ', '.join(roles) if isinstance(roles, list) else roles
                    result.append(f"USER {name} {{role: {roles_str}}}")
                    seen.add(name)
            scope = scope.parent
        return result
    
    def query_user(self, name):
        """Returns information about a specific user."""
        roles = self.lookup_user(name)
        if roles is None:
            return None
        roles_str = ', '.join(roles) if isinstance(roles, list) else roles
        return f"USER {name} {{role: {roles_str}}}"
    
    def query_constants(self):
        """Returns all constants from current scope and parent scopes."""
        result = []
        seen = set()
        scope = self.current_scope
        while scope:
            for name, value in scope.constants.items():
                if name not in seen:
                    if isinstance(value, str):
                        result.append(f"CONST {name} = \"{value}\"")
                    else:
                        result.append(f"CONST {name} = {value}")
                    seen.add(name)
            scope = scope.parent
        return result
    
    def query_constant(self, name):
        """Returns information about a specific constant."""
        value = self.lookup_constant(name)
        if value is None:
            return None
        if isinstance(value, str):
            return f"CONST {name} = \"{value}\""
        else:
            return f"CONST {name} = {value}"
    
    def query_policies(self):
        """Returns all named policies and their rules."""
        result = []
        for name, body in self.named_policies.items():
            # Count policy rules in the body
            rule_count = sum(1 for stmt in body if isinstance(stmt, tuple) and stmt[0] == 'POLICY_RULE')
            result.append(f"POLICY {name} {{ {rule_count} rule(s) }}")
        return result
    
    def query_policy(self, name):
        """Returns information about a specific named policy."""
        if name not in self.named_policies:
            return None
        body = self.named_policies[name]
        result = [f"POLICY {name} {{"]
        for stmt in body:
            if isinstance(stmt, tuple) and stmt[0] == 'POLICY_RULE':
                rule = stmt[1]
                rule_type = rule.get('type', 'UNKNOWN')
                actions = rule.get('actions', [])
                resource = rule.get('resource', '?')
                condition = rule.get('condition')
                if condition:
                    result.append(f"  {rule_type} action: {actions} ON resource: {resource} IF (condition)")
                else:
                    result.append(f"  {rule_type} action: {actions} ON resource: {resource}")
        result.append("}")
        return "\n".join(result)
    
    # --- LEGACY PROPERTIES (for backward compatibility) ---
    @property
    def roles(self):
        """Legacy access: returns roles from current scope"""
        return self.current_scope.roles
    
    @property
    def users(self):
        """Legacy access: returns users from current scope"""
        return self.current_scope.users
    
    @property
    def resources(self):
        """Legacy access: returns resources from current scope"""
        return self.current_scope.resources
    
    @property
    def constants(self):
        """Legacy access: returns constants from current scope"""
        return self.current_scope.constants
    
    def get_all_policies(self):
        """Returns all policies from all scopes (global and nested)"""
        all_policies = []
        # Traverse all scopes in the stack
        for scope in self.scope_stack:
            all_policies.extend(scope.policies)
        return all_policies
    
    @property
    def policies(self):
        """Legacy access: returns all policies from all scopes"""
        return self.get_all_policies()
