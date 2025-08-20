"""
train_model.py
------------------------------------------------
This script generates synthetic data for phishing and benign URLs, 
trains classification and clustering models using PyCaret,
and saves the models and plots for use in the SOAR application. 
It includes workflows for model training, feature importance plotting,
and threat actor profile clustering.
"""
# train_model.py
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from pycaret.classification import (
    setup,
    compare_models,
    finalize_model,
    save_model,
    plot_model,
)
from pycaret.clustering import (
    setup as clu_setup,
    create_model as clu_create,
    save_model as clu_save,
)


def generate_synthetic_data(num_samples=500):
    """Generates a synthetic dataset of phishing and benign URL features,
    including features for three distinct threat actor profiles.
    """

    print("Generating synthetic dataset...")


    # Create data for three distinct threat actor profiles
    #threat_actor_profiles = ["State-Sponsored", "Organized-Cybercrime", "Hacktivist"]

    # Split samples among threat actor profiles
    num_state_sponsored = num_samples // 3
    num_organized_crime = num_samples // 3
    num_hacktivist = num_samples - num_state_sponsored - num_organized_crime
    num_benign = num_samples

    # Generate State-Sponsored profile data (sophisticated attacks)

    #1. State-Sponsored:
    #    Simulate high sophistication. This profile might use valid SSL (SSLfinal_State = 1)
    #    but also deceptive techniques like Prefix_Suffix = 1. Their attacks are subtle
    #    and well-crafted.

    state_sponsored_data = {
        "having_IP_Address": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.1, 0.9]
        ),
        "URL_Length": np.random.choice(
            [1, 0, -1], num_state_sponsored, p=[0.3, 0.6, 0.1]
        ),
        "Shortining_Service": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.2, 0.8]
        ),
        "having_At_Symbol": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.2, 0.8]
        ),
        "double_slash_redirecting": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.1, 0.9]
        ),
        "Prefix_Suffix": np.random.choice([1, -1], num_state_sponsored, p=[0.95, 0.05]),
        "having_Sub_Domain": np.random.choice(
            [1, 0, -1], num_state_sponsored, p=[0.4, 0.5, 0.1]
        ),
        "SSLfinal_State": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.95, 0.05]
        ),
        "URL_of_Anchor": np.random.choice(
            [-1, 0, 1], num_state_sponsored, p=[0.2, 0.3, 0.5]
        ),
        "Links_in_tags": np.random.choice(
            [-1, 0, 1], num_state_sponsored, p=[0.2, 0.3, 0.5]
        ),
        "SFH": np.random.choice([-1, 0, 1], num_state_sponsored, p=[0.3, 0.2, 0.5]),
        "Abnormal_URL": np.random.choice([1, -1], num_state_sponsored, p=[0.3, 0.7]),
        "has_political_keyword": np.random.choice(
            [1, -1], num_state_sponsored, p=[0.1, 0.9]
        ),
    }
    df_state_sponsored = pd.DataFrame(state_sponsored_data)
    df_state_sponsored["threat_profile"] = "State-Sponsored"

    # Generate Organized Cybercrime profile data (high-volume, noisy attacks)
    # 2. Organized Cybercrime:
    #    Simulate high-volume, "noisy" attacks. This profile would frequently use URL
    #    shortening (Shortining_Service = 1), IP addresses (having_IP_Address = 1),
    #    and abnormal URL structures.

    organized_cybercrime_data = {
        "having_IP_Address": np.random.choice(
            [1, -1], num_organized_crime, p=[0.95, 0.05]
        ),
        "URL_Length": np.random.choice(
            [1, 0, -1], num_organized_crime, p=[0.6, 0.3, 0.1]
        ),
        "Shortining_Service": np.random.choice(
            [1, -1], num_organized_crime, p=[0.95, 0.05]
        ),
        "having_At_Symbol": np.random.choice(
            [1, -1], num_organized_crime, p=[0.6, 0.4]
        ),
        "double_slash_redirecting": np.random.choice(
            [1, -1], num_organized_crime, p=[0.5, 0.5]
        ),
        "Prefix_Suffix": np.random.choice([1, -1], num_organized_crime, p=[0.7, 0.3]),
        "having_Sub_Domain": np.random.choice(
            [1, 0, -1], num_organized_crime, p=[0.7, 0.2, 0.1]
        ),
        "SSLfinal_State": np.random.choice(
            [-1, 0, 1], num_organized_crime, p=[0.8, 0.15, 0.05]
        ),
        "URL_of_Anchor": np.random.choice(
            [-1, 0, 1], num_organized_crime, p=[0.7, 0.2, 0.1]
        ),
        "Links_in_tags": np.random.choice(
            [-1, 0, 1], num_organized_crime, p=[0.6, 0.3, 0.1]
        ),
        "SFH": np.random.choice([-1, 0, 1], num_organized_crime, p=[0.8, 0.15, 0.05]),
        "Abnormal_URL": np.random.choice([1, -1], num_organized_crime, p=[0.7, 0.3]),
        "has_political_keyword": np.random.choice(
            [1, -1], num_organized_crime, p=[0.1, 0.9]
        ),
    }
    df_organized_cybercrime = pd.DataFrame(organized_cybercrime_data)
    df_organized_cybercrime["threat_profile"] = "Organized-Cybercrime"

    # Generate Hacktivist profile data (opportunistic attacks with political keywords)

    # 3. Hacktivist:
    #    Simulate opportunistic attacks that often include political keywords. This profile would
    #frequently use URL shortening (Shortining_Service = 1),
    # IP addresses (having_IP_Address = 1),
    # and abnormal URL structures.

    hacktivist_data = {
        "having_IP_Address": np.random.choice([1, -1], num_hacktivist, p=[0.45, 0.55]),
        "URL_Length": np.random.choice([1, 0, -1], num_hacktivist, p=[0.5, 0.3, 0.2]),
        "Shortining_Service": np.random.choice([1, -1], num_hacktivist, p=[0.95, 0.05]),
        "having_At_Symbol": np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),
        "double_slash_redirecting": np.random.choice(
            [1, -1], num_hacktivist, p=[0.4, 0.6]
        ),
        "Prefix_Suffix": np.random.choice([1, -1], num_hacktivist, p=[0.5, 0.5]),
        "having_Sub_Domain": np.random.choice(
            [1, 0, -1], num_hacktivist, p=[0.5, 0.3, 0.2]
        ),
        "SSLfinal_State": np.random.choice(
            [-1, 0, 1], num_hacktivist, p=[0.5, 0.3, 0.2]
        ),
        "URL_of_Anchor": np.random.choice(
            [-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]
        ),
        "Links_in_tags": np.random.choice(
            [-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]
        ),
        "SFH": np.random.choice([-1, 0, 1], num_hacktivist, p=[0.5, 0.3, 0.2]),
        "Abnormal_URL": np.random.choice([1, -1], num_hacktivist, p=[0.5, 0.5]),
        "has_political_keyword": np.random.choice(
            [1, -1], num_hacktivist, p=[0.8, 0.2]
        ),
    }
    df_hacktivist = pd.DataFrame(hacktivist_data)
    df_hacktivist["threat_profile"] = "Hacktivist"

    benign_data = {
        "having_IP_Address": np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        "URL_Length": np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.6, 0.3]),
        "Shortining_Service": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "having_At_Symbol": np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        "double_slash_redirecting": np.random.choice(
            [1, -1], num_benign, p=[0.05, 0.95]
        ),
        "Prefix_Suffix": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "having_Sub_Domain": np.random.choice(
            [1, 0, -1], num_benign, p=[0.1, 0.4, 0.5]
        ),
        "SSLfinal_State": np.random.choice([-1, 0, 1], num_benign, p=[0.05, 0.15, 0.8]),
        "URL_of_Anchor": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        "Links_in_tags": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        "SFH": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.1, 0.8]),
        "Abnormal_URL": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "has_political_keyword": np.random.choice([1, -1], num_benign, p=[0.3, 0.7]),
    }

    df_bengin = pd.DataFrame(benign_data)
    df_bengin["threat_profile"] = "Bengin"
    df_bengin["label"] = 0  # Mark as benign

    threat_actor_profiles_df = pd.concat(
        [df_state_sponsored, df_organized_cybercrime, df_hacktivist], ignore_index=True
    )
    threat_actor_profiles_df["label"] = 1  # Mark as phishing

    # Concatenate all dataframes and shuffle
    final_df = pd.concat([threat_actor_profiles_df, df_bengin], ignore_index=True)
    return final_df.sample(frac=1).reset_index(drop=True)


def cluster_plot(data, kmeans, save_path="models/cluster_plot.png"):
    """
    Generates a 2D cluster plot for the KMeans clustering results.

    Args:
        data (pd.DataFrame): The input dataframe containing features and labels.
        kmeans (KMeans): The trained KMeans model.
        save_path (str): The file path to save the cluster plot.
    """
    features = data.drop(["label", "threat_profile"], axis=1)
    # Debug: Print columns with missing values
    missing_cols = features.columns[features.isnull().any()].tolist()
    if missing_cols:
        print(f"Columns with missing values: {missing_cols}")
        print(features[missing_cols].isnull().sum())
    else:
        print("No missing values detected in features for PCA.")
    pca = PCA(n_components=2)
    reduced = pca.fit_transform(features)
    clusters = kmeans.predict(features)
    plt.figure(figsize=(8, 6))
    scatter = plt.scatter(
        reduced[:, 0], reduced[:, 1], c=clusters, cmap="viridis", alpha=0.7
    )
    plt.title("KMeans Clustering Plot (manual)")
    plt.xlabel("PCA Component 1")
    plt.ylabel("PCA Component 2")
    plt.colorbar(scatter, label="Cluster")
    plt.tight_layout()
    os.makedirs("models", exist_ok=True)
    plt.savefig(save_path)
    plt.close()
    print(f"Manual cluster plot saved to {save_path}")


def clustering_workflow(data):
    """
    Trains a KMeans clustering model to attribute threat actor profiles
    to phishing URLs using PyCaret.

    Args:
        data (pd.DataFrame): The input dataframe containing features and labels for clustering.

    Workflow Steps:
        1. Filters the data to include only phishing samples (label == 1).
        2. Drops non-feature columns ('label', 'threat_profile') for clustering.
        3. Initializes PyCaret clustering setup with normalization.
        4. Creates a KMeans model with 3 clusters (for three threat actor profiles).
        5. Saves the trained clustering model to 'models/kmeans_clustering_model'.
        6. Generates and saves a manual cluster plot to 'models/cluster_plot.png'.

    Outputs:
        - Trained clustering model (.pkl)
        - Cluster plot (.png)
    """

    clustering_model_path = "models/threat_actor_profiles"

    print("\n--- Starting Clustering Workflow for Threat Attribution (KMeans) ---")

    # Filter data realted only threat actor profiles
    threat_actor_profile_df = data[data["label"] == 1].copy()

    # 2) Drop columns that aren’t features
    threat_actor_profile_df = threat_actor_profile_df.drop(
        ["label", "threat_profile"], axis=1
    )

    print("Initializing PyCaret Clustering Setup (KMeans)...")
    # Tip: normalize=True helps KMeans if your features are on different scales
    clu_setup(
        data=threat_actor_profile_df, session_id=42, normalize=True, verbose=False
    )

    print("Creating KMeans clustering model with 3 clusters...")
    kmeans = clu_create("kmeans", num_clusters=3)

    print("Saving clustering model...")
    clustering_model_path = "models/kmeans_clustering_model"
    os.makedirs("models", exist_ok=True)
    clu_save(kmeans, clustering_model_path)
    print("Clustering model saved successfully.")
    cluster_plot(data, kmeans)


def classification_workflow(data):
    """
    Trains a classification model to detect phishing URLs using PyCaret.

    Args:
        data (pd.DataFrame): The input dataframe containing features and labels for training.

    Workflow Steps:
        1. Removes the 'threat_profile' column from the training data to avoid data leakage.
        2. Initializes PyCaret setup for classification with the provided data.
        3. Compares multiple models (Random Forest, Extra Trees, LightGBM) and selects the best one.
        4. Finalizes the best model for deployment.
        5. Plots feature importance and saves the plot to 'models/feature_importance.png'.
        6. Saves the trained model to 'models/phishing_url_detector'.

    Outputs:
        - Trained classification model (saved as a .pkl file)
        - Feature importance plot (saved as a .png file)
    """
    print("\n--- Starting Classification Workflow ---")

    classification_model_path = "models/phishing_url_detector"
    plot_path = "models/feature_importance.png"
    # Workflow 1 - Classification
    print("Workflow 1 - Classificaiton")

    # remove threat_profile column from the training data
    training_data = data.drop(columns=["threat_profile"])

    print("Initializing PyCaret Setup...")
    setup(training_data, target="label", session_id=42, verbose=False)

    print("Comparing models...")
    best_model = compare_models(n_select=1, include=["rf", "et", "lightgbm"])

    print("Finalizing model...")
    final_model = finalize_model(best_model)

    # NEW: Plot feature importance and save it to a file
    print("Saving feature importance plot...")
    os.makedirs("models", exist_ok=True)
    plot_model(final_model, plot="feature", save=True)
    # PyCaret saves it as 'Feature Importance.png', let's rename it
    os.rename("Feature Importance.png", plot_path)

    print("Saving model...")
    save_model(final_model, classification_model_path)
    print("Model and plot saved successfully.")


def train():
    """
    Orchestrates the end-to-end training pipeline for phishing URL detection
    and threat actor clustering.

    Workflow Steps:
        1. Deletes any existing classification model to ensure retraining from scratch.
    2. Generates synthetic data simulating phishing and benign URLs,
       including threat actor profiles.
        3. Saves the generated data to 'data/phishing_synthetic.csv'.
        4. Trains a classification model and saves the model and feature importance plot.
    5. Trains a clustering model for threat actor attribution and saves
       the model and cluster plot.

    Outputs:
        - Trained classification model (.pkl)
        - Feature importance plot (.png)
        - Trained clustering model (.pkl)
        - Cluster plot (.png)
        - Synthetic dataset (.csv)
    """

    print("Training model...")
    print("Generating synthetic data...")
    data = generate_synthetic_data()
    os.makedirs("data", exist_ok=True)
    data.to_csv("data/phishing_synthetic.csv", index=False)

    #Workflow 1 - Classification
    classification_workflow(data)

    # Workflow 2 - Clustering
    clustering_workflow(data)

if __name__ == "__main__":
    train()
