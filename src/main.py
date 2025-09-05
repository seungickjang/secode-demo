try:
    num1 = float("10")  # Initialize num1 with a valid string for compilation
    num2 = float("20")  # Initialize num2 with a valid string for compilation
except ValueError:
    raise ValueError("Input values must be valid numbers.")

def add_numbers(num1, num2):
    if num1 is None or num1 == '':
        raise ValueError("num1 cannot be None or empty")
    if num2 is None or num2 == '':
        raise ValueError("num2 cannot be None or empty")
    
    try:
        num1 = float(num1)
        num2 = float(num2)
    except ValueError:
        raise ValueError("Input values must be valid numbers.")
    
    return num1 + num2

# Example usage
result = add_numbers("10", "20")
print(result)  # Output: 30.0