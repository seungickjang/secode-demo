def add_numbers(num1, num2):
    if num1 is None or num2 is None:
        return "Invalid input: None values are not allowed."
    
    try:
        num1 = float(num1)
        num2 = float(num2)
    except ValueError:
        return "Invalid input: Please enter valid numbers."
    
    return num1 + num2