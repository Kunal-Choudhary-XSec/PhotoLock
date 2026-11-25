from io import BytesIO

from flask import Flask, jsonify, render_template, request, send_file
from PIL import Image, UnidentifiedImageError

from stego import StegoError, decode_message, encode_message

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def load_png(upload):
    if not upload or not upload.filename:
        raise ValueError("Choose a PNG image first.")

    try:
        image = Image.open(upload.stream)
        if image.format != "PNG":
            raise ValueError("The image must be a PNG file.")
        image.load()
        return image.convert("RGBA")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("The uploaded file is not a valid image.") from exc


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/hide", methods=["POST"])
def hide():
    try:
        image = load_png(request.files.get("image"))
        message = request.form.get("message", "").strip()
        password = request.form.get("password", "")

        if not message:
            raise ValueError("Enter a message to hide.")
        if not password:
            raise ValueError("Enter a password to protect the message.")

        encoded_image = encode_message(image, message, password)
        output = BytesIO()
        encoded_image.save(output, format="PNG")
        output.seek(0)
        return send_file(
            output,
            mimetype="image/png",
            as_attachment=True,
            download_name="photolock_image.png",
        )
    except (StegoError, ValueError) as exc:
        if request.headers.get("X-PhotoLock-Request") == "async":
            return jsonify(error=str(exc)), 400
        return render_template("index.html", hide_error=str(exc)), 400


@app.route("/reveal", methods=["POST"])
def reveal():
    try:
        image = load_png(request.files.get("image"))
        password = request.form.get("password", "")
        if not password:
            raise ValueError("Enter the password used to hide the message.")

        message = decode_message(image, password)
        if request.headers.get("X-PhotoLock-Request") == "async":
            return jsonify(message=message)
        return render_template("index.html", revealed_message=message)
    except (StegoError, ValueError) as exc:
        if request.headers.get("X-PhotoLock-Request") == "async":
            return jsonify(error=str(exc)), 400
        return render_template("index.html", reveal_error=str(exc)), 400


@app.errorhandler(413)
def file_too_large(_error):
    message = "The uploaded file is too large (16 MB maximum)."
    if request.headers.get("X-PhotoLock-Request") == "async":
        return jsonify(error=message), 413
    return render_template(
        "index.html", general_error=message
    ), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
