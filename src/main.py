from html import escape

def process_user_input(user_input):
    # Process the user input here
    result = user_input  # Example processing
    return escape(str(result))  # Mitigated XSS vulnerability