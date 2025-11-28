"""Quick system test - writes results to test_results.txt"""
import sys

def test_all():
    results = []
    
    # Test 1: Lexer
    try:
        from lexer import lexer
        lexer.input("ROLE Admin {can: *}")
        tokens = list(lexer)
        results.append(("✅ Lexer", "OK - " + str(len(tokens)) + " tokens"))
    except Exception as e:
        results.append(("❌ Lexer", str(e)))
    
    # Test 2: Parser
    try:
        from parser import parser
        code = "ROLE Admin {can: *}\nRESOURCE DB {path: \"/data\"}\nUSER Jane { role: Admin }"
        result = parser.parse(code)
        if result:
            results.append(("✅ Parser", "OK - Parsed " + str(len(result[1])) + " statements"))
        else:
            results.append(("⚠️ Parser", "Returned None"))
    except Exception as e:
        results.append(("❌ Parser", str(e)))
    
    # Test 3: Error Handling
    try:
        from parser import parser
        import io
        from contextlib import redirect_stdout
        invalid = "ROLE Admin can: *}"
        f = io.StringIO()
        with redirect_stdout(f):
            parser.parse(invalid)
        output = f.getvalue()
        if "SYNTAX ERROR" in output:
            results.append(("✅ Error Handling", "OK - Detects syntax errors"))
        else:
            results.append(("⚠️ Error Handling", "No error detected"))
    except Exception as e:
        results.append(("❌ Error Handling", str(e)))
    
    # Test 4: Semantics
    try:
        from semantics import SemanticAnalyzer
        analyzer = SemanticAnalyzer()
        code = "ROLE Admin {can: *}\nUSER Jane { role: Admin }"
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            analyzer.run(code)
        results.append(("✅ Semantics", "OK - " + str(len(analyzer.errors)) + " errors"))
    except Exception as e:
        results.append(("❌ Semantics", str(e)))
    
    # Test 5: Security Scanner
    try:
        from security_rules import SecurityScanner
        from symbol_table import SymbolTable
        symtab = SymbolTable()
        symtab.define_role("Admin", "ALL")
        scanner = SecurityScanner(symtab)
        risks = scanner.scan()
        results.append(("✅ Security Scanner", "OK - " + str(len(risks)) + " risks"))
    except Exception as e:
        results.append(("❌ Security Scanner", str(e)))
    
    # Test 6: Evaluator
    try:
        from evaluator import PolicyEvaluator
        context = {'time': {'hour': 10}, 'user': {'role': 'Admin'}}
        evaluator = PolicyEvaluator(context)
        results.append(("✅ Evaluator", "OK - Initialized"))
    except Exception as e:
        results.append(("❌ Evaluator", str(e)))
    
    # Test 7: Gemini Helper
    try:
        from gemini_helper import get_gemini_helper
        helper = get_gemini_helper()
        if helper:
            results.append(("✅ Gemini Helper", "OK - Initialized with API key"))
        else:
            results.append(("⚠️ Gemini Helper", "No API key (expected)"))
    except Exception as e:
        results.append(("❌ Gemini Helper", str(e)))
    
    # Test 8: App imports
    try:
        import streamlit
        import pandas
        results.append(("✅ Dependencies", "OK - streamlit, pandas"))
    except Exception as e:
        results.append(("❌ Dependencies", str(e)))
    
    # Write results
    with open("test_results.txt", "w") as f:
        f.write("="*60 + "\n")
        f.write("SPL IDE - SYSTEM TEST RESULTS\n")
        f.write("="*60 + "\n\n")
        
        passed = 0
        for name, status in results:
            f.write(f"{name}: {status}\n")
            if "✅" in name:
                passed += 1
        
        f.write("\n" + "="*60 + "\n")
        f.write(f"Total: {passed}/{len(results)} tests passed\n")
        f.write("="*60 + "\n")
    
    # Also print to console
    print("="*60)
    print("SPL IDE - SYSTEM TEST RESULTS")
    print("="*60)
    print()
    for name, status in results:
        print(f"{name}: {status}")
    print()
    print("="*60)
    print(f"Total: {passed}/{len(results)} tests passed")
    print("="*60)
    print("\nDetailed results written to test_results.txt")
    
    return passed == len(results)

if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)

