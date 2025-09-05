from html import escape

def generate_response(user_input):
    # Process user input
    result = user_input  # Assume some processing happens here
    # Escape the result to prevent XSS
    return escape(str(result))