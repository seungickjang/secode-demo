from flask import Flask, request

app = Flask(__name__)

@app.route('/calculate', methods=['GET'])
def calculate():
    try:
        num1 = float(request.args.get('num1', 0))  # Default to 0 if not provided
        if num1 < 0:
            raise ValueError("num1 must be a non-negative number.")
    except ValueError:
        return "Invalid input for num1. Please provide a non-negative number.", 400

    try:
        num2 = float(request.args.get('num2', 0))  # Default to 0 if not provided
        if num2 < 0:
            raise ValueError("num2 must be a non-negative number.")
    except ValueError:
        return "Invalid input for num2. Please provide a non-negative number.", 400

    result = num1 + num2
    return f"The result is {result}"

if __name__ == '__main__':
    app.run()