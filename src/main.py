import html

def generate_response(result):
    # Sanitize the output to prevent XSS
    return html.escape(str(result))

# Example usage
if __name__ == "__main__":
    user_input = "<script>alert('XSS');</script>"
    print(generate_response(user_input))