import html

def add_numbers(num1, num2):
    # Ensure inputs are integers
    try:
        num1 = int(num1)
        num2 = int(num2)
    except ValueError:
        return "Invalid input. Please provide integers."
    
    # Return the result after escaping it to prevent XSS
    return html.escape(str(num1 + num2))

# Example usage
if __name__ == "__main__":
    print(add_numbers(5, 10))  # Output: 15