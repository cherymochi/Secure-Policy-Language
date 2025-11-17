"""
Secure Policy Language (SPL) - Abstract Syntax Tree (AST) Node Classes
University of Technology, Jamaica - CIT4004
Analysis of Programming Languages Project

Team Members:
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

This module defines all AST node classes that represent the structure
of parsed SPL programs. Each grammar rule maps to a corresponding node class.
"""


# ============================================
# BASE AST NODE CLASS
# ============================================
class ASTNode:
    """
    Base class for all AST nodes.
    All nodes inherit from this class and track line numbers for error reporting.
    """
    def __init__(self, line_num=0):
        self.line_number = line_num
    
    def __repr__(self):
        return f"{self.__class__.__name__}(line={self.line_number})"


# ============================================
# PROGRAM NODE
# ============================================
class ProgramNode(ASTNode):
    """
    Root node representing an entire SPL program.
    Contains a list of declarations (roles, users, resources, policies).
    """
    def __init__(self, declarations, line_num=0):
        super().__init__(line_num)
        self.declarations = declarations  # List of declaration nodes
    
    def __repr__(self):
        return f"ProgramNode({len(self.declarations)} declarations)"


# ============================================
# DECLARATION NODES
# ============================================
class RoleDefNode(ASTNode):
    """
    Represents a role definition.
    Example: ROLE Admin {can: *}
    """
    def __init__(self, name, actions, line_num=0):
        super().__init__(line_num)
        self.name = name          # String: 'Admin'
        self.actions = actions    # List of strings or ['*'] for wildcard
    
    def __repr__(self):
        actions_str = '*' if self.actions == ['*'] else ', '.join(self.actions)
        return f"RoleDefNode(name='{self.name}', actions=[{actions_str}])"


class UserDefNode(ASTNode):
    """
    Represents a user definition.
    Example: USER JaneDoe {role: Developer}
    """
    def __init__(self, name, role, line_num=0):
        super().__init__(line_num)
        self.name = name  # String: 'JaneDoe'
        self.role = role  # String: 'Developer'
    
    def __repr__(self):
        return f"UserDefNode(name='{self.name}', role='{self.role}')"


class ResourceDefNode(ASTNode):
    """
    Represents a resource definition.
    Example: RESOURCE DB_Finance {path: "/data/financial"}
    """
    def __init__(self, name, path, line_num=0):
        super().__init__(line_num)
        self.name = name  # String: 'DB_Finance'
        self.path = path  # String: '/data/financial'
    
    def __repr__(self):
        return f"ResourceDefNode(name='{self.name}', path='{self.path}')"


class PolicyNode(ASTNode):
    """
    Represents a policy definition (ALLOW or DENY).
    Example: ALLOW action: read, write ON resource: DB_Finance IF (time.hour > 9)
    """
    def __init__(self, policy_type, actions, resources, condition=None, line_num=0):
        super().__init__(line_num)
        self.policy_type = policy_type  # String: 'ALLOW' or 'DENY'
        self.actions = actions          # List of strings: ['read', 'write'] or ['*']
        self.resources = resources      # String or list: 'DB_Finance' or '/data/*'
        self.condition = condition      # ConditionNode or None
    
    def __repr__(self):
        actions_str = '*' if self.actions == ['*'] else ', '.join(self.actions)
        cond_str = f", condition={self.condition}" if self.condition else ""
        return f"PolicyNode(type='{self.policy_type}', actions=[{actions_str}], resources='{self.resources}'{cond_str})"


# ============================================
# EXPRESSION NODES
# ============================================
class ConditionNode(ASTNode):
    """
    Represents a boolean condition (AND/OR).
    Example: time.hour > 9 AND time.hour < 17
    """
    def __init__(self, operator, left, right, line_num=0):
        super().__init__(line_num)
        self.operator = operator  # String: 'AND' or 'OR'
        self.left = left          # ComparisonNode or ConditionNode
        self.right = right        # ComparisonNode or ConditionNode
    
    def __repr__(self):
        return f"ConditionNode(operator='{self.operator}', left={self.left}, right={self.right})"


class ComparisonNode(ASTNode):
    """
    Represents a comparison expression.
    Example: time.hour > 9, user.role == Admin
    """
    def __init__(self, operator, left, right, line_num=0):
        super().__init__(line_num)
        self.operator = operator  # String: '==', '!=', '<', '>', '<=', '>='
        self.left = left          # ArithmeticExprNode or AttributeAccessNode or LiteralNode
        self.right = right        # ArithmeticExprNode or AttributeAccessNode or LiteralNode
    
    def __repr__(self):
        return f"ComparisonNode(operator='{self.operator}', left={self.left}, right={self.right})"


class ArithmeticExprNode(ASTNode):
    """
    Represents an arithmetic expression with binary operators.
    Example: 3 + 4 * 10, time.hour * 2 + 5
    """
    def __init__(self, operator, left, right, line_num=0):
        super().__init__(line_num)
        self.operator = operator  # String: '+', '-', '*', '/'
        self.left = left          # ArithmeticExprNode, FactorNode, or LiteralNode
        self.right = right        # ArithmeticExprNode, FactorNode, or LiteralNode
    
    def __repr__(self):
        return f"ArithmeticExprNode(operator='{self.operator}', left={self.left}, right={self.right})"


class UnaryExprNode(ASTNode):
    """
    Represents a unary expression (+ or -).
    Example: -5, +10
    """
    def __init__(self, operator, operand, line_num=0):
        super().__init__(line_num)
        self.operator = operator  # String: '+' or '-'
        self.operand = operand    # FactorNode or LiteralNode
    
    def __repr__(self):
        return f"UnaryExprNode(operator='{self.operator}', operand={self.operand})"


class AttributeAccessNode(ASTNode):
    """
    Represents attribute access (dot notation).
    Example: time.hour, user.role
    """
    def __init__(self, object_name, attribute_name, line_num=0):
        super().__init__(line_num)
        self.object_name = object_name      # String: 'time'
        self.attribute_name = attribute_name  # String: 'hour'
    
    def __repr__(self):
        return f"AttributeAccessNode(object='{self.object_name}', attribute='{self.attribute_name}')"


# ============================================
# LITERAL NODES
# ============================================
class IdentifierNode(ASTNode):
    """
    Represents an identifier (variable name, role name, etc.).
    Example: Admin, JaneDoe, DB_Finance
    """
    def __init__(self, value, line_num=0):
        super().__init__(line_num)
        self.value = value  # String
    
    def __repr__(self):
        return f"IdentifierNode(value='{self.value}')"


class NumberNode(ASTNode):
    """
    Represents a number literal.
    Example: 9, 17, 100
    """
    def __init__(self, value, line_num=0):
        super().__init__(line_num)
        self.value = value  # Integer
    
    def __repr__(self):
        return f"NumberNode(value={self.value})"


class StringNode(ASTNode):
    """
    Represents a string literal.
    Example: "/data/financial", "read"
    """
    def __init__(self, value, line_num=0):
        super().__init__(line_num)
        self.value = value  # String
    
    def __repr__(self):
        return f"StringNode(value='{self.value}')"


class WildcardNode(ASTNode):
    """
    Represents a wildcard (*) in action lists.
    Example: {can: *}
    """
    def __init__(self, line_num=0):
        super().__init__(line_num)
        self.value = '*'  # Always '*'
    
    def __repr__(self):
        return "WildcardNode()"


# ============================================
# VISUALIZATION METHODS
# ============================================
def print_ast(node, indent=0, prefix=""):
    """
    Pretty-print the AST tree structure.
    Useful for debugging and documentation.
    """
    if node is None:
        return
    
    # Print current node
    print("  " * indent + prefix + str(node))
    
    # Recursively print children
    if isinstance(node, ProgramNode):
        for i, decl in enumerate(node.declarations):
            is_last = (i == len(node.declarations) - 1)
            print_ast(decl, indent + 1, "├── " if not is_last else "└── ")
    
    elif isinstance(node, ConditionNode):
        print_ast(node.left, indent + 1, "├── ")
        print_ast(node.right, indent + 1, "└── ")
    
    elif isinstance(node, ComparisonNode):
        print_ast(node.left, indent + 1, "├── ")
        print_ast(node.right, indent + 1, "└── ")
    
    elif isinstance(node, ArithmeticExprNode):
        print_ast(node.left, indent + 1, "├── ")
        print_ast(node.right, indent + 1, "└── ")
    
    elif isinstance(node, UnaryExprNode):
        print_ast(node.operand, indent + 1, "└── ")
    
    elif isinstance(node, PolicyNode):
        if node.condition:
            print_ast(node.condition, indent + 1, "└── condition: ")


def ast_to_dict(node):
    """
    Convert AST node to dictionary representation.
    Useful for JSON serialization and LLM integration.
    """
    if node is None:
        return None
    
    result = {
        'type': node.__class__.__name__,
        'line': node.line_number
    }
    
    if isinstance(node, ProgramNode):
        result['declarations'] = [ast_to_dict(d) for d in node.declarations]
    
    elif isinstance(node, RoleDefNode):
        result['name'] = node.name
        result['actions'] = node.actions
    
    elif isinstance(node, UserDefNode):
        result['name'] = node.name
        result['role'] = node.role
    
    elif isinstance(node, ResourceDefNode):
        result['name'] = node.name
        result['path'] = node.path
    
    elif isinstance(node, PolicyNode):
        result['policy_type'] = node.policy_type
        result['actions'] = node.actions
        result['resources'] = node.resources
        if node.condition:
            result['condition'] = ast_to_dict(node.condition)
    
    elif isinstance(node, ConditionNode):
        result['operator'] = node.operator
        result['left'] = ast_to_dict(node.left)
        result['right'] = ast_to_dict(node.right)
    
    elif isinstance(node, ComparisonNode):
        result['operator'] = node.operator
        result['left'] = ast_to_dict(node.left)
        result['right'] = ast_to_dict(node.right)
    
    elif isinstance(node, ArithmeticExprNode):
        result['operator'] = node.operator
        result['left'] = ast_to_dict(node.left)
        result['right'] = ast_to_dict(node.right)
    
    elif isinstance(node, UnaryExprNode):
        result['operator'] = node.operator
        result['operand'] = ast_to_dict(node.operand)
    
    elif isinstance(node, AttributeAccessNode):
        result['object'] = node.object_name
        result['attribute'] = node.attribute_name
    
    elif isinstance(node, IdentifierNode):
        result['value'] = node.value
    
    elif isinstance(node, NumberNode):
        result['value'] = node.value
    
    elif isinstance(node, StringNode):
        result['value'] = node.value
    
    elif isinstance(node, WildcardNode):
        result['value'] = '*'
    
    return result


# ============================================
# TESTING
# ============================================
if __name__ == "__main__":
    # Example: Create a simple AST manually
    print("Creating example AST...")
    print("=" * 60)
    
    # ROLE Admin {can: *}
    role = RoleDefNode(
        name="Admin",
        actions=["*"],
        line_num=1
    )
    
    # USER JaneDoe {role: Developer}
    user = UserDefNode(
        name="JaneDoe",
        role="Developer",
        line_num=2
    )
    
    # RESOURCE DB_Finance {path: "/data/financial"}
    resource = ResourceDefNode(
        name="DB_Finance",
        path="/data/financial",
        line_num=3
    )
    
    # ALLOW action: read, write ON resource: DB_Finance IF (time.hour > 9)
    condition = ComparisonNode(
        operator=">",
        left=AttributeAccessNode("time", "hour", line_num=5),
        right=NumberNode(9, line_num=5),
        line_num=5
    )
    
    policy = PolicyNode(
        policy_type="ALLOW",
        actions=["read", "write"],
        resources="DB_Finance",
        condition=condition,
        line_num=4
    )
    
    # Create program
    program = ProgramNode(
        declarations=[role, user, resource, policy],
        line_num=0
    )
    
    # Print AST
    print("\nAST Structure:")
    print_ast(program)
    
    # Print as dictionary
    print("\n" + "=" * 60)
    print("AST as Dictionary (for JSON/LLM):")
    import json
    print(json.dumps(ast_to_dict(program), indent=2))

