from flask import Flask, request, jsonify, render_template
import os
import joblib
import pandas as pd
import pefile
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static', template_folder='templates')
UPLOAD_FOLDER = './uploads'  # Correct folder name
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Function to extract features from executable files
def extract_exe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        features = {
            "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "VersionInformationSize": pe.OPTIONAL_HEADER.SizeOfHeaders,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "SectionsMaxEntropy": max(section.get_entropy() for section in pe.sections),
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "ResourcesMaxEntropy": max(
                section.get_entropy() for section in pe.sections if section.Name.startswith(b'.rsrc')),
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "SectionsMeanEntropy": sum(section.get_entropy() for section in pe.sections) / len(pe.sections),
            "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "ResourcesMinEntropy": min(
                section.get_entropy() for section in pe.sections if section.Name.startswith(b'.rsrc')),
            "SectionsMinEntropy": min(section.get_entropy() for section in pe.sections),
        }
        return features
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

# Function to predict whether the file is malware
def predict_malware(file_path):
    model = joblib.load('./backend/model_latest.pkl')

    features = extract_exe_features(file_path)
    if not features:
        return "Error"

    feature_columns = ['DllCharacteristics', 'Machine', 'Characteristics', 
                       'VersionInformationSize', 'ImageBase', 'MajorSubsystemVersion', 
                       'SectionsMaxEntropy', 'Subsystem', 'ResourcesMaxEntropy', 
                       'SizeOfOptionalHeader', 'SectionsMeanEntropy', 'MajorOperatingSystemVersion', 
                       'ResourcesMinEntropy', 'SectionsMinEntropy']

    features_df = pd.DataFrame([features], columns=feature_columns).fillna(0)
    prediction = model.predict(features_df)
    return 'Malware' if prediction[0] == 0 else 'Safe'

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle file upload and malware detection
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'ft' not in request.files:
        return jsonify({'error': 'No file part in the request'})

    file = request.files['ft']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'})

    # Save the file temporarily
    # file_path = os.path.join('./uploads', file.filename)
    # os.makedirs('o./uplads', exist_ok=True)
    filename = secure_filename(file.filename)
    file_path = os.path.join("./uploads", filename)
    if not os.path.exists(file_path):
        file.save(file_path)

    # Predict malware
    result = predict_malware(file_path)

    # Clean up the uploaded file
    #os.remove(file_path)
    
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)