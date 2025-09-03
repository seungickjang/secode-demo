from flask import Flask, request
from html import escape

app = Flask(__name__)

@app.route('/calculate', methods=['POST'])
def calculate():
    # Assume input is coming from a JSON body
    data = request.get_json()
    result = data.get('value', 0)  # Default to 0 if 'value' is not provided
    return escape(str(result))  # Escape the output to prevent XSS

if __name__ == '__main__':
    app.run()