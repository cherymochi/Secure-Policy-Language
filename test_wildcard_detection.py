"""
Test script to verify wildcard vs multiplication detection
"""
import lexer

test_cases = [
    # Wildcard cases
    ("Wildcard in role", "ROLE Admin {can: *}", "WILDCARD"),
    ("Wildcard in action", "ALLOW action: * ON resource: DB_Finance", "WILDCARD"),
    ("Wildcard in list", "ROLE Admin {can: read, *}", "WILDCARD"),
    
    # Multiplication cases
    ("Simple multiplication", "3 * 4", "TIMES"),
    ("Multiplication with identifiers", "time.hour * 2", "TIMES"),
    ("Multiplication in expression", "3 + 4 * 10", "TIMES"),
    ("Multiplication in parentheses", "(a * b)", "TIMES"),
    ("Complex arithmetic", "time.hour * 2 + 5", "TIMES"),
    
    # Edge cases
    ("Wildcard at end", "ROLE Admin {can: *}", "WILDCARD"),
    ("Multiplication after identifier", "x * y", "TIMES"),
    ("Wildcard in nested braces", "ROLE Admin {can: {permissions: *}}", "WILDCARD"),
]

print("=" * 70)
print("Testing Wildcard vs Multiplication Detection")
print("=" * 70)

all_passed = True
for test_name, test_code, expected_token in test_cases:
    lexer.lexer.input(test_code)
    tokens = list(lexer.lexer)
    
    # Find the * token
    asterisk_tokens = [t for t in tokens if t.value == '*']
    
    if asterisk_tokens:
        actual_token = asterisk_tokens[0].type
        status = "✓" if actual_token == expected_token else "✗"
        if actual_token != expected_token:
            all_passed = False
        
        print(f"\n{status} {test_name}")
        print(f"   Input: {test_code}")
        print(f"   Expected: {expected_token}, Got: {actual_token}")
        if actual_token != expected_token:
            print(f"   All tokens: {[(t.type, t.value) for t in tokens]}")
    else:
        print(f"\n✗ {test_name}")
        print(f"   Input: {test_code}")
        print(f"   ERROR: No * token found!")
        all_passed = False

print("\n" + "=" * 70)
if all_passed:
    print("✓ All tests passed!")
else:
    print("✗ Some tests failed")
print("=" * 70)

