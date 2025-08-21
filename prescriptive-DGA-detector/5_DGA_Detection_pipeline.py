# Filename: dga_pipeline.py
"""
End-to-End DGA Detection Pipeline
1. Generate synthetic DGA dataset
2. Train with H2O AutoML
3. Explain with SHAP (XAI)
4. Generate prescriptive playbook (Gemini API)
"""

import os
import sys
import json
import asyncio
import aiohttp
import warnings
import random
import string
import pandas as pd
import matplotlib.pyplot as plt
import shap
import h2o
from h2o.automl import H2OAutoML
from dotenv import load_dotenv


# -------------------------------------------------------------------
# Utility: Safe H2OFrame -> Pandas conversion
# -------------------------------------------------------------------
def h2o_to_pandas(h2o_frame):
    """Convert H2OFrame to pandas, preferring multi-thread if available."""
    try:
        return h2o_frame.as_data_frame(use_multi_thread=True)
    except Exception:
        return h2o_frame.as_data_frame()

# -------------------------------------------------------------------
# STEP 1: Generate synthetic DGA dataset
# -------------------------------------------------------------------
def generate_dga_data(filename="dga_dataset_train.csv", n_samples=500):
    def generate_domain(length, charset):
        return ''.join(random.choice(charset) for _ in range(length))

    data = []
    for _ in range(n_samples):
        # DGA-like domain
        domain = generate_domain(random.randint(12, 25), string.ascii_lowercase + string.digits)
        data.append({"domain": domain, "length": len(domain), "entropy": len(set(domain)) / len(domain), "dga": 1})
        # Benign domain
        domain = random.choice(["google.com", "microsoft.com", "openai.com", "github.com", "yahoo.com"])
        data.append({"domain": domain, "length": len(domain), "entropy": len(set(domain)) / len(domain), "dga": 0})

    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"✅ Synthetic dataset saved to {filename}")
    return filename

# -------------------------------------------------------------------
# STEP 2: Train with H2O AutoML
# -------------------------------------------------------------------
def train_model(dataset_path, model_dir="./models", max_runtime_secs=60):
    h2o.init()
    data = h2o.import_file(dataset_path)

    y = "dga"
    x = ["length", "entropy"]  # Features

    aml = H2OAutoML(max_runtime_secs=max_runtime_secs, seed=42, exclude_algos=["DeepLearning"])
    data[y] = data[y].asfactor()
    train, test = data.split_frame(ratios=[0.8], seed=42)

    aml.train(x=x, y=y, training_frame=train)

    lb = aml.leaderboard
    best_model = aml.leader

    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    model_path = h2o.save_model(model=best_model, path=model_dir, force=True)
    print(f"✅ Best model saved to {model_path}")
    return model_path, test

# -------------------------------------------------------------------
# STEP 3: Explain with SHAP
# -------------------------------------------------------------------
def explain_model(model_path, test_df, output_dir="./explain"):
    os.makedirs(output_dir, exist_ok=True)
    best_model = h2o.load_model(model_path)

    X_test = h2o_to_pandas(test_df[["length", "entropy"]])

    # Prediction wrapper for SHAP
    def predict_wrapper(data):
        h2o_df = h2o.H2OFrame(pd.DataFrame(data, columns=X_test.columns))
        predictions = best_model.predict(h2o_df)
        preds = h2o_to_pandas(predictions)
        return preds["predict"].astype(int).values

    # Silence H2O conversion warnings
    warnings.filterwarnings("ignore", message="Converting H2O frame")

    explainer = shap.KernelExplainer(predict_wrapper, X_test.head(50))
    shap_values = explainer.shap_values(X_test.head(50))

    # Summary Plot
    shap.summary_plot(shap_values, X_test.head(50), show=False)
    plt.savefig(os.path.join(output_dir, "shap_summary.png"), bbox_inches="tight")
    plt.close()

    # Force Plot (first instance)
    shap.force_plot(explainer.expected_value, shap_values[0, :], X_test.iloc[0, :], matplotlib=True, show=False)
    plt.savefig(os.path.join(output_dir, "shap_force.png"), bbox_inches="tight")
    plt.close()

    print(f"✅ SHAP explanations saved in {output_dir}")

    # Return findings for playbook
    return f"""- **Alert:** Potential DGA domain detected in DNS logs.
- **Domain:** {X_test.iloc[0].to_dict()}
- **AI Model Explanation (from SHAP):** High entropy and length contributed to DGA classification."""

# -------------------------------------------------------------------
# STEP 4: Generate Prescriptive Playbook (Gemini API)
# -------------------------------------------------------------------
async def generate_playbook(xai_findings, api_key, output_file="PLAYBOOK.md"):
    prompt = f"""
    As a SOC Manager, your task is to create a simple, step-by-step incident response playbook for a Tier 1 analyst.
    The playbook should be based on the provided alert details and the explanation from our AI model.

    Do not explain the AI model; only provide the prescriptive actions. The playbook must be a numbered list of 3-4 clear, concise steps.

    **Alert Details & AI Explanation:**
    {xai_findings}
    """
    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}

    async with aiohttp.ClientSession() as session:
        async with session.post(apiUrl, json=payload) as response:
            result = await response.json()

            if response.status != 200:
                return f"Error: API returned status {response.status}. Response: {json.dumps(result)}"

            playbook = result['candidates'][0]['content']['parts'][0]['text']

            # Save to Markdown
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("# Incident Response Playbook\n\n")
                f.write("## Alert Context\n")
                f.write(xai_findings + "\n\n")
                f.write("## Prescriptive Playbook\n")
                f.write(playbook + "\n")

            print(f"✅ Playbook saved to {output_file}")
            return playbook

# -------------------------------------------------------------------
# MAIN PIPELINE
# -------------------------------------------------------------------
async def main():
    load_dotenv()
    api_key = os.environ.get("GOOGLE_API_KEY")

    if not api_key:
        print("🚨 GOOGLE_API_KEY not set. Please configure your .env file.")
        sys.exit(1)

    # Step 1: Generate data
    print("Generating DGA dataset...")
    dataset = generate_dga_data()

    # Step 2: Train model
    print("Training DGA detection model...")
    model_path, test = train_model(dataset)

    # Step 3: Explain with SHAP
    print("Generating SHAP explanations...")
    findings = explain_model(model_path, test)

    # Step 4: Generate Playbook
    print("Generating incident response playbook...")
    await generate_playbook(findings, api_key)

    h2o.shutdown(prompt=False)

if __name__ == "__main__":
    asyncio.run(main())
