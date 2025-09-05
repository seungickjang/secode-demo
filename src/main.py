import html

def process_user_input(user_input):
    # Process the user input here
    result = user_input  # Example processing
    return html.escape(str(result))  # Mitigated XSS vulnerability

# Example usage
if __name__ == "__main__":
    user_input = "<script>alert('XSS');</script>"  # Simulated user input
    print(process_user_input(user_input))