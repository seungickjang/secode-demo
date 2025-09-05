from flask import Flask, request
import math

app = Flask(__name__)
@app.route('/compute', methods=['GET'])
def compute():
    try:
        num1 = float(request.args.get('num1'))
        num2 = float(request.args.get('num2'))
        result = 1 / (num1 + num2)
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}
if __name__ == '__main__':
    app.run(debug=True)
