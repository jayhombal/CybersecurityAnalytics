# train_model.py
import pandas as pd
import numpy as np
from pycaret.classification import setup, compare_models, finalize_model, save_model, plot_model
from pycaret.clustering import setup as clu_setup, create_model as clu_create, save_model as clu_save, assign_model as clu_assign_model, plot_model as clu_plot_model
import os
import matplotlib.pyplot as plt
from sklearn.metrics import silhouette_score
import os
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt


def generate_synthetic_data(num_samples=500):
    """ Generates a synthetic dataset of phishing and benign URL features,
        including features for three distinct threat actor profiles.
    """

    print("Generating synthetic dataset...")

    features = [
        'having_IP_Address', 'URL_Length', 'Shortining_Service',
        'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
        'having_Sub_Domain', 'SSLfinal_State', 'URL_of_Anchor', 'Links_in_tags',
        'SFH', 'Abnormal_URL'
    ]

    """
    Threat Actor Profiles:
    1. State-Sponsored:
        Simulate high sophistication. This profile might use valid SSL (SSLfinal_State = 1)
        but also deceptive techniques like Prefix_Suffix = 1. Their attacks are subtle
        and well-crafted.
    2. Organized Cybercrime:
        Simulate high-volume, "noisy" attacks. This profile would frequently use URL
        shortening (Shortining_Service = 1), IP addresses (having_IP_Address = 1),
        and abnormal URL structures.
    3. Hacktivist:
        Simulate opportunistic attacks. This profile might use a mix of tactics and
        could be represented by a new feature you invent (e.g., has_political_keyword = 1).
    """
    
    # Create data for three distinct threat actor profiles
    threat_actor_profiles = ['State-Sponsored', 'Organized-Cybercrime', 'Hacktivist']

    # Split samples among threat actor profiles
    num_state_sponsored = num_samples // 3
    num_organized_crime = num_samples // 3
    num_hacktivist = num_samples - num_state_sponsored - num_organized_crime
    num_benign = num_samples

    # Generate State-Sponsored profile data (sophisticated attacks)
    """
    1. State-Sponsored:
        Simulate high sophistication. This profile might use valid SSL (SSLfinal_State = 1)
        but also deceptive techniques like Prefix_Suffix = 1. Their attacks are subtle
        and well-crafted.
    """
    state_sponsored_data = {
        'having_IP_Address': np.random.choice([1, -1], num_state_sponsored, p=[0.1, 0.9]),  # Rarely use IP addresses
        'URL_Length': np.random.choice([1, 0, -1], num_state_sponsored, p=[0.3, 0.6, 0.1]),  # Moderate length URLs
        'Shortining_Service': np.random.choice([1, -1], num_state_sponsored, p=[0.2, 0.8]),  # Rarely use URL shortening
        'having_At_Symbol': np.random.choice([1, -1], num_state_sponsored, p=[0.2, 0.8]),  # Rarely use @ symbol
        'double_slash_redirecting': np.random.choice([1, -1], num_state_sponsored, p=[0.1, 0.9]),  # Rarely use double slash
        'Prefix_Suffix': np.random.choice([1, -1], num_state_sponsored, p=[0.95, 0.05]),  # Often use prefix/suffix deception
        'having_Sub_Domain': np.random.choice([1, 0, -1], num_state_sponsored, p=[0.4, 0.5, 0.1]),  # Moderate subdomain use
        'SSLfinal_State': np.random.choice([1, -1], num_state_sponsored, p=[0.95, 0.05]),  # Often use valid SSL
        'URL_of_Anchor': np.random.choice([-1, 0, 1], num_state_sponsored, p=[0.2, 0.3, 0.5]),  # Often legitimate anchors
        'Links_in_tags': np.random.choice([-1, 0, 1], num_state_sponsored, p=[0.2, 0.3, 0.5]),  # Often legitimate links
        'SFH': np.random.choice([-1, 0, 1], num_state_sponsored, p=[0.3, 0.2, 0.5]),  # Mixed SFH usage
        'Abnormal_URL': np.random.choice([1, -1], num_state_sponsored, p=[0.3, 0.7]),  # Less abnormal URLs
        'has_political_keyword': np.random.choice([1, -1], num_state_sponsored, p=[0.1, 0.9]),  # Rarely political
        'threat_profile': ['State-Sponsored'] * num_state_sponsored
    }
    df_state_sponsored = pd.DataFrame(state_sponsored_data)
    df_state_sponsored['threat_profile'] = 'State-Sponsored'

    # Generate Organized Cybercrime profile data (high-volume, noisy attacks)
    """
    2. Organized Cybercrime:
        Simulate high-volume, "noisy" attacks. This profile would frequently use URL
        shortening (Shortining_Service = 1), IP addresses (having_IP_Address = 1),
        and abnormal URL structures.
    """
    organized_cybercrime_data = {
        'having_IP_Address': np.random.choice([1, -1], num_organized_crime, p=[0.95, 0.05]),  # Often use IP addresses
        'URL_Length': np.random.choice([1, 0, -1], num_organized_crime, p=[0.6, 0.3, 0.1]),  # Often long URLs
        'Shortining_Service': np.random.choice([1,-1], num_organized_crime, p=[0.95, 0.05]),  # Often use URL shortening
        'having_At_Symbol': np.random.choice([1, -1], num_organized_crime, p=[0.6, 0.4]),  # Often use @ symbol
        'double_slash_redirecting': np.random.choice([1, -1], num_organized_crime, p=[0.5, 0.5]),  # Mixed double slash usage
        'Prefix_Suffix': np.random.choice([1, -1], num_organized_crime, p=[0.7, 0.3]),  # Often use prefix/suffix
        'having_Sub_Domain': np.random.choice([1, 0, -1], num_organized_crime, p=[0.7, 0.2, 0.1]),  # Often use subdomains
        'SSLfinal_State': np.random.choice([-1, 0, 1], num_organized_crime, p=[0.8, 0.15, 0.05]),  # Rarely valid SSL
        'URL_of_Anchor': np.random.choice([-1, 0, 1], num_organized_crime, p=[0.7, 0.2, 0.1]),  # Often suspicious anchors
        'Links_in_tags': np.random.choice([-1, 0, 1], num_organized_crime, p=[0.6, 0.3, 0.1]),  # Often suspicious links
        'SFH': np.random.choice([-1, 0, 1], num_organized_crime, p=[0.8, 0.15, 0.05]),  # Often suspicious SFH
        'Abnormal_URL': np.random.choice([1, -1], num_organized_crime, p=[0.7, 0.3]),  # Often abnormal URLs
        'has_political_keyword': np.random.choice([1, -1], num_organized_crime, p=[0.1, 0.9]),  # Rarely political
        'threat_profile': ['Organized-Cybercrime'] * num_organized_crime
    }
    df_organized_cybercrime = pd.DataFrame(organized_cybercrime_data)
    df_organized_cybercrime['threat_profile'] = 'Organized-Cybercrime'

    # Generate Hacktivist profile data (opportunistic attacks with political keywords)
    """
    3. Hacktivist:
        Simulate opportunistic attacks that often include political keywords. This profile would
        frequently use URL shortening (Shortining_Service = 1), IP addresses (having_IP_Address = 1),
        and abnormal URL structures.
    """
    hacktivist_data = {
        'having_IP_Address': np.random.choice([1, -1], num_hacktivist, p=[0.45, 0.55]),  # Moderate IP address use
        'URL_Length': np.random.choice([1, 0, -1], num_hacktivist, p=[0.5, 0.3, 0.2]),  # Mixed URL lengths
        'Shortining_Service': np.random.choice([1, -1], num_hacktivist, p=[0.95, 0.05]),  # Mixed shortening usage
        'having_At_Symbol': np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),  # Moderate @ symbol use
        'double_slash_redirecting': np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),  # Less double slash
        'Prefix_Suffix': np.random.choice([1, -1], num_hacktivist, p=[0.5, 0.5]),  # Often use prefix/suffix
        'having_Sub_Domain': np.random.choice([1, 0, -1], num_hacktivist, p=[0.5, 0.3, 0.2]),  # Mixed subdomain use
        'SSLfinal_State': np.random.choice([-1, 0, 1], num_hacktivist, p=[0.5, 0.3, 0.2]),  # Mixed SSL usage
        'URL_of_Anchor': np.random.choice([-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]),  # Mixed anchor usage
        'Links_in_tags': np.random.choice([-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]),  # Mixed link usage
        'SFH': np.random.choice([-1, 0, 1], num_hacktivist, p=[0.5, 0.3, 0.2]),  # Mixed SFH usage
        'Abnormal_URL': np.random.choice([1, -1], num_hacktivist, p=[0.5, 0.5]),  # Mixed abnormal URLs
        'has_political_keyword': np.random.choice([1, -1], num_hacktivist, p=[0.8, 0.2]),  # Often political keywords
        'threat_profile': ['Hacktivist'] * num_hacktivist
    }
    df_hacktivist = pd.DataFrame(hacktivist_data)
    df_hacktivist['threat_profile'] = 'Hacktivist'

    benign_data = {
        'having_IP_Address': np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        'URL_Length': np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.6, 0.3]),
        'Shortining_Service': np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        'having_At_Symbol': np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        'double_slash_redirecting': np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        'Prefix_Suffix': np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        'having_Sub_Domain': np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.4, 0.5]),
        'SSLfinal_State': np.random.choice([-1, 0, 1], num_benign, p=[0.05, 0.15, 0.8]),
        'URL_of_Anchor': np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        'Links_in_tags': np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        'SFH': np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.1, 0.8]),
        'Abnormal_URL': np.random.choice([1, -1], num_benign, p=[0.1, 0.9])
    }
    
    df_bengin = pd.DataFrame(hacktivist_data)
    df_bengin['threat_profile'] = 'Bengin'
    df_bengin['label'] = 0  # Mark as benign

    threat_actor_profiles_df = pd.concat([df_state_sponsored, df_organized_cybercrime, df_hacktivist], ignore_index=True)
    threat_actor_profiles_df['label'] = 1  # Mark as phishing

    # Concatenate all dataframes and shuffle
    final_df = pd.concat([threat_actor_profiles_df, df_bengin], ignore_index=True)
    return final_df.sample(frac=1).reset_index(drop=True)


def cluster_plot(data, kmeans, save_path='models/cluster_plot.png'):
    features = data.drop(['label', 'threat_profile'], axis=1)
    pca = PCA(n_components=2)
    reduced = pca.fit_transform(features)
    clusters = kmeans.predict(features)
    plt.figure(figsize=(8,6))
    scatter = plt.scatter(reduced[:,0], reduced[:,1], c=clusters, cmap='viridis', alpha=0.7)
    plt.title('KMeans Clustering Plot (manual)')
    plt.xlabel('PCA Component 1')
    plt.ylabel('PCA Component 2')
    plt.colorbar(scatter, label='Cluster')
    plt.tight_layout()
    os.makedirs('models', exist_ok=True)
    plt.savefig(save_path)
    plt.close()
    print(f"Manual cluster plot saved to {save_path}")
          

def clustering_workflow(data):
    clustering_model_path = 'models/threat_actor_profiles'

    print("\n--- Starting Clustering Workflow for Threat Attribution (KMeans) ---")

    # Filter data realted only threat actor profiles
    threat_actor_profile_df = data[data['label'] == 1].copy()

    # 2) Drop columns that aren’t features
    threat_actor_profile_df = threat_actor_profile_df.drop(['label', 'threat_profile'], axis=1)

    print("Initializing PyCaret Clustering Setup (KMeans)...")
    # Tip: normalize=True helps KMeans if your features are on different scales
    s_clust = clu_setup(
        data=threat_actor_profile_df,
        session_id=42,
        normalize=True,
        verbose=False
    )

    print("Creating KMeans clustering model with 3 clusters...")
    kmeans = clu_create('kmeans', num_clusters=3)

    print("Saving clustering model...")
    clustering_model_path = 'models/kmeans_clustering_model'
    os.makedirs('models', exist_ok=True)
    clu_save(kmeans, clustering_model_path)
    print("Clustering model saved successfully.")
    cluster_plot(data,kmeans)

    # cluster_plot_path = 'models/cluster_plot.png'
    # print(f"Saving cluster plot to {cluster_plot_path}...")
    # clu_plot_model(kmeans, plot='cluster', save=True)

    # print(f"Current working directory: {os.getcwd()}")
    # print("Files in working directory after plotting:")
    # for f in os.listdir(os.getcwd()):
    #     print(f"  - {f}")
    # if os.path.exists('Cluster_Plot.png'):
    #     os.rename('Cluster_Plot.png', cluster_plot_path)


def classification_workflow(data):
    
    classification_model_path = 'models/phishing_url_detector'
    plot_path = 'models/feature_importance.png'
    
    # Workflow 1 - Classification
    print("Workflow 1 - Classificaiton")

    # remove threat_profile column from the training data
    training_data = data.drop(columns=['threat_profile'])

    print("Initializing PyCaret Setup...")
    s = setup(training_data, target='label', session_id=42, verbose=False)

    print("Comparing models...")
    best_model = compare_models(n_select=1, include=['rf', 'et', 'lightgbm'])

    print("Finalizing model...")
    final_model = finalize_model(best_model)

    # NEW: Plot feature importance and save it to a file
    print("Saving feature importance plot...")
    os.makedirs('models', exist_ok=True)
    plot_model(final_model, plot='feature', save=True)
    # PyCaret saves it as 'Feature Importance.png', let's rename it
    os.rename('Feature Importance.png', plot_path)

    print("Saving model...")
    save_model(final_model, classification_model_path)
    print(f"Model and plot saved successfully.")


def train():

    print("Training model...")
    classification_model_path = 'models/phishing_url_detector'
    clustering_model_path = 'models/threat_actor_profiles'
    plot_path = 'models/feature_importance.png'

    if os.path.exists(classification_model_path + '.pkl'):
        print("Model exists. Deleting old model and retraining...")
        os.remove(classification_model_path + '.pkl')

    print("Generating synthetic data...")
    data = generate_synthetic_data()
    os.makedirs('data', exist_ok=True)
    data.to_csv('data/phishing_synthetic.csv', index=False)

    # Workflow 1 - Classification
    classification_workflow(data)

    # Workflow 2 - Clustering
    clustering_workflow(data)

    

if __name__ == "__main__":
    train()