import html

def add_numbers(num1, num2):
    # Ensure inputs are integers
    if not isinstance(num1, int) or not isinstance(num2, int):
        raise ValueError("Both inputs must be integers.")
    
    # Return the sum as a sanitized string
    return html.escape(str(num1 + num2))

# Example usage
if __name__ == "__main__":
    print(add_numbers(5, 10))  # Output: 15