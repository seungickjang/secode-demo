def safe_divide(num1, num2):
    if num1 is None or num2 is None or not isinstance(num1, (int, float)) or not isinstance(num2, (int, float)):
        raise ValueError("Both num1 and num2 must be valid numbers.")
    
    if num2 == 0:
        raise ValueError("Cannot divide by zero.")
    
    return num1 / num2

# Example usage
try:
    result = safe_divide(10, 2)
    print("Result:", result)
except ValueError as e:
    print("Error:", e)