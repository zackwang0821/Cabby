from flask import Flask, request, redirect, url_for, render_template
import os

app = Flask(__name__)
UPLOAD_FOLDER = r'Folder'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file:
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
