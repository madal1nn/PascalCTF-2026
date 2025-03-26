from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pages/<int:index>")
def page(index):
    return render_template("pages.html", index=index)

@app.route("/api/get_json", methods=["POST"])
def get_json():
    index = request.json.get("index")
    if not index:
        return jsonify({"error": "Index is required"}), 400
    
    path = f"static/{index}"
    try:
        with open(path, "r") as file:
            data = file.read()
        return data, 200
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
