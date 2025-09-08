def get_float_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            value = float(user_input)
            if value < 0:  # Example of additional validation (e.g., non-negative numbers)
                raise ValueError("Input must be a non-negative number.")
            return value
        except ValueError as e:
            print(f"Invalid input: {e}. Please enter a valid number.")

num1 = get_float_input("Enter the first number: ")
num2 = get_float_input("Enter the second number: ")