def add_numbers(num1, num2):
    if num1.replace('.', '', 1).isdigit() and num2.replace('.', '', 1).isdigit():
        try:
            float_num1 = float(num1)
            float_num2 = float(num2)
        except ValueError:
            raise ValueError("Invalid input: Please enter valid numbers.")
        
        return float_num1 + float_num2
    else:
        raise ValueError("Invalid input: Please enter valid numbers.")

# Example usage
try:
    result = add_numbers("10", "20")
    print("The sum is:", result)
except ValueError as e:
    print(e)