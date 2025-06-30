from flask import Flask, render_template, request
import pickle

app = Flask(__name__)

# Load pickled models/vectorizers
email_model = pickle.load(open('models/email_model.pkl', 'rb'))
email_vectorizer = pickle.load(open('models/email_vectorizer.pkl', 'rb'))
sms_model = pickle.load(open('models/sms_model.pkl', 'rb'))
sms_vectorizer = pickle.load(open('models/sms_vectorizer.pkl', 'rb'))
url_model = pickle.load(open('models/url_model.pkl', 'rb'))
url_vectorizer = pickle.load(open('models/url_vectorizer.pkl', 'rb'))

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        data_type = request.form['data_type']
        user_input = request.form['user_input']
        if data_type == 'email':
            vect = email_vectorizer.transform([user_input])
            pred = email_model.predict(vect)[0]
        elif data_type == 'sms':
            vect = sms_vectorizer.transform([user_input])
            pred = sms_model.predict(vect)[0]
        elif data_type == 'url':
            vect = url_vectorizer.transform([user_input])
            pred = url_model.predict(vect)[0]
        else:
            pred = None
        if pred is not None:
            result = 'Phishing' if pred == 1 else 'Legitimate'
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
