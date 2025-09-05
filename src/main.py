def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def add_numbers(num1, num2):
    if not is_float(num1) or not is_float(num2):
        raise ValueError("Both inputs must be numbers or numeric strings.")
    
    return float(num1) + float(num2)

# Example usage
try:
    result = add_numbers("3.14", "2.71")
    print(f"The result is: {result}")
except ValueError as e:
    print(e)