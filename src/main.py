import html

def calculate(a, b):
    # Perform some calculation
    result = a + b
    # Return the result with HTML escaping to prevent XSS
    return html.escape(str(result))

# Example usage
if __name__ == "__main__":
    print(calculate(5, 3))  # Output: 8