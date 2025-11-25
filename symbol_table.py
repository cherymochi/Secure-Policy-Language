# symbol_table.py

class SymbolTable:
    def __init__(self):
        # --- 1. MEMORY STORAGE ---
        self.roles = {}       # Stores role_name -> scope
        self.users = {}       # Stores user_name -> role_name
        self.resources = {}   # Stores resource_name -> path
        self.policies = []    # Stores policy rules

        # --- 2. SCOPE CONTEXT (With Types) ---
        # Defines valid attributes and their expected types.
        # Matches requirement: "syntax... focused on attributes" 
        self.context = {
            'time':  {
                'hour': 'int', 
                'minute': 'int', 
                'day': 'str', 
                'year': 'int'
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

    # --- DEFINITION METHODS ---

    def define_role(self, name, scope):
        """Stores a role definition."""
        if name in self.roles:
            raise ValueError(f"Error: Role '{name}' is already defined.")
        self.roles[name] = scope
        print(f"[SymbolTable] Role defined: {name}")

    def define_resource(self, name, path):
        """Stores a resource definition."""
        if name in self.resources:
            raise ValueError(f"Error: Resource '{name}' is already defined.")
        self.resources[name] = path
        print(f"[SymbolTable] Resource defined: {name}")

    def define_user(self, name, role_name):
        """
        Binds a user to a role.
        Performs Semantic Check: Does the role exist?
        """
        if name in self.users:
            raise ValueError(f"Error: User '{name}' is already defined.")

        if role_name not in self.roles:
            raise ValueError(f"Error: Cannot assign undefined role '{role_name}' to user '{name}'.")
        self.users[name] = role_name
        print(f"[SymbolTable] User defined: {name} -> Role: {role_name}")

    def add_policy(self, policy_node):
        """
        Stores a policy rule.
        Performs Semantic Check: Does the resource exist?
        """
        resource_name = policy_node['resource']
        if resource_name not in self.resources:
            raise ValueError(f"Error: Policy refers to undefined resource '{resource_name}'.")
        
        self.policies.append(policy_node)
        print(f"[SymbolTable] Policy added for resource: {resource_name}")

    # --- SCOPE RESOLUTION METHODS ---

    def resolve_variable(self, var_name):
        """Checks if a top-level variable exists in the scope."""
        if var_name not in self.context:
             return False
        return True

    def resolve_attribute(self, obj, attr):
        """
        Checks if an object.attribute pair exists and returns its type.
        Returns None if invalid.
        """
        if obj not in self.context:
            return None
        if attr not in self.context[obj]:
            return None
        return self.context[obj][attr]
    
    def __str__(self):
        return (f"\n--- SYMBOL TABLE STATE ---\n"
                f"Roles:     {list(self.roles.keys())}\n"
                f"Users:     {self.users}\n"
                f"Resources: {self.resources}\n"
                f"Policies:  {len(self.policies)} rules loaded\n"
                f"--------------------------")

# --- UNIT TEST ---
if __name__ == "__main__":
    print("Testing Symbol Table independently...")
    st = SymbolTable()
    try:
        st.define_role("Admin", "ALL")
        st.define_user("Jane", "SuperGod") # Should Fail
    except ValueError as e:
        print(f"Caught Expected Error: {e}")