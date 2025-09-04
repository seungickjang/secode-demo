import html

def process_user_input(user_input):
    # Process the user input safely
    result = user_input  # Assume some processing happens here
    return html.escape(str(result))  # Escape the output to prevent XSS

# Example usage
if __name__ == "__main__":
    user_input = "<script>alert('XSS');</script>"  # Simulated user input
    print(process_user_input(user_input))  # This will safely output the user input