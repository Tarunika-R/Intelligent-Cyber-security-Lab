import os, pickle
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def train_save(text_col, label_col, dataset_path, model_path, vec_path, model_type="nb"):
    df = pd.read_csv(dataset_path)
    X, y = df[text_col], df[label_col]
    vec = CountVectorizer()
    X_vec = vec.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)
    if model_type == "rf":
        model = RandomForestClassifier(n_estimators=100, random_state=42)
    else:
        model = MultinomialNB()
    model.fit(X_train, y_train)
    print(f"Saved {model_type} model to {model_path}")
    pickle.dump(model, open(model_path, 'wb'))
    pickle.dump(vec, open(vec_path, 'wb'))

os.makedirs('models', exist_ok=True)

train_save('body', 'label', 'datasets/email_dataset_1.csv', 'models/email_model.pkl', 'models/email_vectorizer.pkl', 'nb')
train_save('text', 'label', 'datasets/sms_dataset_1.csv', 'models/sms_model.pkl', 'models/sms_vectorizer.pkl', 'nb')
train_save('URL', 'Label', 'datasets/url_dataset_1.csv', 'models/url_model.pkl', 'models/url_vectorizer.pkl', 'rf')
