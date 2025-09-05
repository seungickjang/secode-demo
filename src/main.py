import html

def calculate(num1, num2):
    try:
        result = num1 + num2
        return f"The result is: {html.escape(str(result))}"
    except Exception as e:
        return f"An error occurred: {html.escape(str(e))}"

# Example usage
if __name__ == "__main__":
    print(calculate(5, 10))  # This should print: The result is: 15