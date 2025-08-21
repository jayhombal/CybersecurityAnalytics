# Filename: 6_test_domain.py
# This script uses the exported H2O MOJO model to classify domains,
# generate SHAP explanations, and create prescriptive incident response playbooks.

import sys
import h2o
import argparse
import math
import os
import requests
import time
import pandas as pd
import re
from h2o.frame import H2OFrame
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

def get_entropy(s):
    """Calculates the Shannon entropy of a string."""
    p, lns = {}, float(len(s))
    for c in s:
        p[c] = p.get(c, 0) + 1
    return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

def featurize_domain(domain):
    """Simple feature extraction for domain names."""
    features = {
        "length": len(domain),
        "entropy": get_entropy(domain),
        "num_dots": domain.count('.'),
        "num_hyphens": domain.count('-'),
        "num_digits": sum(c.isdigit() for c in domain)
    }
    return pd.DataFrame([features])

def sanitize_filename(name):
    """Sanitize domain name to safe filename."""
    return re.sub(r'[^A-Za-z0-9_-]', '_', name)

def generate_playbook(xai_findings):
    """Generates an incident response playbook using a generative AI model."""
    load_dotenv()  # Load environment variables from .env file
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("🚨 GEMINI_API_KEY not set. Aborting.")
        sys.exit(1)

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"

    prompt = f""" Based on the following AI model explanation of a security alert, generate a concise,
    prescriptive incident response playbook. The playbook should be a step-by-step guide for a 
    cybersecurity analyst. AI Model Explanation:{xai_findings} Playbook:"""

    payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}

    retries = 0
    while retries < 5:
        response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
        if response.status_code == 429:
            sleep_time = 2 ** retries
            print(f"API rate limit exceeded. Retrying in {sleep_time}s...")
            time.sleep(sleep_time)
            retries += 1
            continue
        response.raise_for_status()
        break
    else:
        return "Failed to generate playbook due to API issues."

    result = response.json()
    if result.get('candidates'):
        return result['candidates'][0]['content']['parts'][0]['text']
    return "Failed to generate playbook. AI response empty."

def main():
    parser = argparse.ArgumentParser(description="Analyze domains with MOJO + SHAP + AI playbooks.")
    parser.add_argument("domains", type=str, nargs='*', help="One or more domains to analyze")
    parser.add_argument("--domain_file", type=str, help="Path to a text file containing domains (one per line)")
    args = parser.parse_args()

    # Collect all domains
    domains = args.domains or []
    if args.domain_file:
        with open(args.domain_file, "r") as f:
            file_domains = [line.strip() for line in f if line.strip()]
        domains.extend(file_domains)

    if not domains:
        print("No domains provided. Exiting.")
        sys.exit(1)

    h2o.init(max_mem_size="2G")

    # Load MOJO model from the training script path
    mojo_path = os.path.join("model", "DGA_Leader.zip")
    if not os.path.exists(mojo_path):
        print(f"Error: MOJO model not found at {mojo_path}.")
        print("Please run the training script (1_train_and_export.py) first.")
        h2o.shutdown(prompt=False)
        return

    print(f"Loading MOJO model from {mojo_path}...")
    mojo_model = h2o.import_mojo(mojo_path)

    for domain in domains:
        print(f"\n=== Analyzing domain: {domain} ===")

        # Featurize input domain
        df_features = featurize_domain(domain)
        h2o_frame = H2OFrame(df_features)

        # Run inference
        prediction = mojo_model.predict(h2o_frame)
        pred_class = prediction.as_data_frame()['predict'][0]
        pred_probs = prediction.as_data_frame().drop(columns='predict').to_dict(orient='records')[0]

        print(f"Predicted Class: {pred_class}")
        print(f"Prediction Probabilities: {pred_probs}")

        # Generate SHAP explanation
        shap_values = mojo_model.predict_contributions(h2o_frame)
        shap_df = shap_values.as_data_frame()
        xai_summary = shap_df.to_dict(orient='records')[0]
        xai_text = f"SHAP Contributions for {domain}:\n" + "\n".join(f"{k}: {v:.4f}" for k,v in xai_summary.items())

        print("\n--- SHAP Explanation ---")
        print(xai_text)

        # Generate AI playbook
        playbook = generate_playbook(xai_text)
        print("\n--- AI-Generated Playbook ---")
        print(playbook)

        # Save to domain-specific file
        safe_domain = sanitize_filename(domain)
        filename = f"PLAYBOOK_{safe_domain}.md"
        with open(filename, "w") as f:
            f.write(f"# Domain Analysis Playbook for {domain}\n\n")
            f.write(f"## Prediction\nClass: {pred_class}\n\nProbabilities: {pred_probs}\n\n")
            f.write("## SHAP Explanation\n")
            f.write(xai_text + "\n\n")
            f.write("## AI-Generated Playbook\n")
            f.write(playbook + "\n")

        print(f"\n✅ Playbook saved to {filename}")

    h2o.shutdown(prompt=False)

if __name__ == "__main__":
    main()
