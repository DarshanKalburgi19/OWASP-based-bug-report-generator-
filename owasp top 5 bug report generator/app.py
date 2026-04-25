"""
OWASP Top 5 Smart Bug Report Generator
Flask Backend - app.py
A logic-driven, template-based security report generator.
"""

from flask import Flask, request, jsonify, render_template
from report_engine import generate_report, validate_inputs

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the main application page."""
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def generate():
    """
    POST endpoint that accepts vulnerability data and returns a structured report.
    Expects JSON body with vulnerability type and associated fields.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Validate inputs before processing
    validation_result = validate_inputs(data)
    if not validation_result["valid"]:
        return jsonify({"error": validation_result["message"]}), 422

    # Generate the full report using logic-based engine
    report = generate_report(data)
    return jsonify(report), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
