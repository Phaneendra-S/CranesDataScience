#now i want to make streamlit app with only top features 
import streamlit as st
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse

# Load the dataset
model=joblib.load('phishing_model.pkl')
# scaler=joblib.load('scaler.pkl')

# --- FEATURE FUNCTIONS ---
def url_length(url):
    """Returns the length of the URL."""
    return len(url)

def hostname_length(url):
    """Returns the length of the hostname in the URL."""
    try:
        return len(urlparse(url).netloc)
    except:
        return 0
    
def path_length(url):
    """Returns the length of the path in the URL."""
    try:
        return len(urlparse(url).path)
    except:
        return 0

def fd_length(url):
    try:
        return len(urlparse(url).path.split('/')[1])
    except:
        return 0
    
def query_length(url):
    """Returns the length of the query string in the URL."""
    try:
        return len(urlparse(url).query)
    except:
        return 0

def count_dir(url):
    return urlparse(url).path.count('/')

def count_subdomains(url):
    netloc = urlparse(url).netloc
    subdomains = netloc.split('.')
    true_subdomains = [part for part in subdomains if part != '']
    if len(true_subdomains) > 2:
        return len(true_subdomains) - 2  # exclude domain and TLD
    return 0

def digit_count(url):
    return sum(char.isdigit() for char in url)

# df['path_entropy'] = df['url'].apply(lambda x: -sum([(x.count(c) / len(x))**2 for c in set(x)]))
def path_entropy(url):
    set_url = set(url)
    return -sum([(url.count(c) / len(url))**2 for c in set_url]) if len(url) > 0 else 0

def extract_features(url):
    characters_to_count = ['-', '@', '?', '%', '.', '=']
    features = {
        'https_count': url.count('https'),
        'www_count': url.count('www'),
        'true_subdomain_count': count_subdomains(url),
        'hostname_length': hostname_length(url),
        'path_length': path_length(url),
        'url_length': url_length(url),
        'spcl_char_count': sum(url.count(c) for c in characters_to_count),
        'fd_length': fd_length(url),
        'http_count': url.count('http'),
        'path_entropy': path_entropy(url)
        # 'query_length': query_length(url),
        # 'digits_count': digit_count(url),
        # 'count_dir': count_dir(url)       
    }
    return pd.DataFrame([features])

# --- STREAMLIT UI ---

st.title("🔍 Phishing URL Detection App")
st.markdown("Enter a URL to check if it's **Phishing** or **Legitimate**.")

url_input = st.text_input("Enter URL", "")

if st.button("Check"):
    if url_input.strip() == "":
        st.warning("Please enter a URL.")
    else:
        # Load model
        with open("phishing_model.pkl", "rb") as f:
            model = joblib.load(f)

        # Extract features
        features_df = extract_features(url_input)

        # Predict
        prediction = model.predict(features_df)[0]
        label = "🔴 Phishing" if prediction == 1 else "🟢 Legitimate"

        # Show result
        st.subheader("Prediction:")
        st.success(label)
