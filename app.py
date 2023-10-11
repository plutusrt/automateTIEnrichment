from flask import Flask, render_template, request, redirect, url_for
import main

app = Flask(__name__)


# Route to render the HTML form
@app.route('/')
def index():
    return render_template('form.html')


# Route to handle form submission
@app.route('/process_parameter', methods=['POST'])
def process_parameter():
    param_value = request.form['param']
    print("Searching for: " + param_value)
    results = main.f(param_value)
    # You can process the parameter here
    # For this example, we'll just print it
    print(f"Received parameter: {param_value}")

    # You can redirect the user to another page or show a response here
    return render_template('results.html', results = results)


if __name__ == '__main__':
    app.run(debug=True)