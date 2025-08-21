# Filename: 3_explain_model.py
import h2o
import shap
import pandas as pd
import matplotlib.pyplot as plt
import warnings

# Suppress H2O dependency warnings if multi-thread libs are not available
warnings.filterwarnings("ignore", category=UserWarning, message="Converting H2O frame")

h2o.init()

# Load best model
model_path = "./models/best_dga_model"
best_model = h2o.load_model(model_path)

# Load test data
test_df = pd.read_csv("dga_dataset_train.csv")
X_test = test_df[['length', 'entropy']]

# --- Prediction wrapper for SHAP ---
def predict_wrapper(data):
    """Wraps H2O model predict for SHAP."""
    h2o_df = h2o.H2OFrame(pd.DataFrame(data, columns=X_test.columns))
    predictions = best_model.predict(h2o_df)
    # Convert safely with multi-thread if possible
    try:
        return predictions.as_data_frame(use_multi_thread=True)["dga"].values
    except TypeError:
        return predictions.as_data_frame()["dga"].values

# --- SHAP Explainer ---
explainer = shap.KernelExplainer(predict_wrapper, X_test.head(50))
shap_values = explainer.shap_values(X_test.head(50))

# --- Summary Plot ---
print("Displaying SHAP Summary Plot (Global Explanation)...")
shap.summary_plot(shap_values, X_test.head(50), show=False)
plt.savefig("shap_summary.png", bbox_inches="tight")
plt.close()

# --- Force Plot ---
print("Displaying SHAP Force Plot (Local Explanation for first instance)...")
force_plot = shap.force_plot(
    explainer.expected_value,
    shap_values[0, :],
    X_test.iloc[0, :],
    matplotlib=True,
    show=False
)
plt.savefig("shap_force.png", bbox_inches="tight")
plt.close()

h2o.shutdown(prompt=False)

