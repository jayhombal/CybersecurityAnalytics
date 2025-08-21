# INSTALL.md

## Getting Started

Follow these steps to set up and use the DGA Detection and Incident Response Playbook Generator.

---

### Prerequisites

- **Python 3.x** installed  
- Install required libraries:
<code>
    pip install h2o requests python-dotenv
</code>
---

### Step 1: Configure Gemini API Key

1. Obtain an API key from [Google AI Studio](https://aistudio.google.com/).
2. In your project’s root directory, create a file named `.env`.
3. Add your API key in the following format:

---

### Step 2: Train and Export the Model

1. Run the training script to build the DGA detection model and export it:

2. This will create a `model/` folder with the exported model files, including `DGA_Leader.zip` (the MOJO model used for predictions).

---

### Step 3: Analyze Domains & Generate Playbooks

Use the analysis script to classify a domain. If a domain is identified as DGA-generated, the system will provide a SHAP explanation and generate a response playbook with the Gemini API.

- **Example: Legitimate Domain**
The script will classify the domain as “legit” and exit (no playbook)._

- **Example: Suspected DGA Domain**
The script classifies the domain as “dga,” outputs a SHAP explanation, and creates a prescriptive incident response playbook via Gemini._

---

**You’re now ready to use the project!** If you have questions, please check the code comments and documentation.