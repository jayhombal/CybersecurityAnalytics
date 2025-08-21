# Prescriptive DGA Detection & Incident Response

This project will automate your cybersecurity workflow by combining a machine learning model for detecting Domain Generation Algorithms (DGAs) with a generative AI solution that creates an effective incident response playbook.

---
**What are Domain Generation Algorithms (DGAs)?**
DGAs are algorithms used by malware to periodically generate a large number of domain names that can be used as rendezvous points with their command and control (C&C) servers. Instead of hard-coding C&C domains, malware uses DGAs to create pseudo-random domain names.

**Why Attackers Use DGAs?**
**Evasion:** Hard to blacklist thousands of generated domains
**Resilience:** If some domains are blocked, others still work
**Cost-effective:** Attackers only register a few of the generated domains
**Dynamic:** Can change algorithms to stay ahead of detection

Common DGA Characteristics:
- High entropy (randomness)
- Unusual character combinations
- Long domain names
- Non-pronounceable strings
- Mathematical patterns

---

## Project Goal

The main purpose of this project is to make it easy for security teams to detect and respond quickly to threats caused by DGAs. Malware often uses DGAs to come up with many different domain names for command-and-control (C2) channels, making it difficult for anyone to block every suspicious site. 
Here, we train a model to catch such DGA domains—like those that appear random or have high entropy—so they can be flagged as malicious. When a model spots a DGA domain, it then uses generative AI to create a clear, step-by-step incident response plan, so teams know exactly how to act.

---

## Architecture Overview

This project works in three main stages:

### 1. Training & Export (1_train_and_export.py)
- **Data Generation**  
  A sample dataset is created with both legitimate and DGA domains. Features such as the length of the domain and Shannon entropy (which checks how random the domain looks) are calculated for each one.

- **Model Training**  
  An H2O AutoML model is trained using this data. This helps us classify domains as legit or DGA. AutoML will try different algorithms and settings to find the best fit, so you do not have to manually tune everything.

- **Model Export**  
  The best performing model is exported in two formats:
  - **MOJO**: This is a handy file (DGA_Leader.zip) meant for fast, production use. You do not need the whole H2O setup to run predictions.
  - **H2O Native Format**: This is the full model for advanced analysis or if you want to continue training.

---

### 2. Analysis & Response (2_analyze_domain.py)
- **Model Loading**  
  The script loads the MOJO model for quick domain analysis.

- **Prediction**  
  When you give a domain name as input, the script checks its features and helps decide if it is a DGA or not.

- **XAI (Explainable AI)**  
  If the input is flagged as DGA, SHAP (SHapley Additive exPlanations) will be used to show why the model made this choice. This is very helpful for human analysts who want to understand the reason behind the prediction.

- **AI-to-AI Bridge**  
  The explanation from SHAP is fed into Gemini, Google’s generative AI. This step bridges the gap between technical AI and human action, turning the explanation into a human-friendly security plan.

- **Prescriptive Playbook Generation**  
  Gemini uses these SHAP findings to generate a simple, clear, and practical incident response playbook. This guide is written in a way that analysts can use immediately, making the response swift and effective.

---

With this project, you are equipped to move from detecting DGA-based threats to acting on them, all in an automated and reliable manner.