# Domain Analysis Testing Workflow

This document describes the steps involved when running the domain analysis script:

```bash
python 6_test_domain.py google.com sdjhskdh.com
```

It also lists the output files generated.

---

## 1. Input

- Domains provided as command-line arguments:
  - `google.com`
  - `sdjhskdh.com`

- Optional input from a domain file (not used in this example).

---

## 2. Workflow Steps

### Step 1: Initialize H2O
- H2O runtime is started to load the MOJO model and run predictions.

### Step 2: Load MOJO Model
- Path used: `model/DGA_Leader.zip`
- If the MOJO model does not exist, the script exits with an error.
- Loaded using `h2o.import_mojo(mojo_path)`.

### Step 3: Loop Over Each Domain
For each domain:

#### a. Featurization
- Compute features:
  - `length` → length of domain
  - `entropy` → Shannon entropy
  - `num_dots` → number of dots
  - `num_hyphens` → number of hyphens
  - `num_digits` → number of digits

#### b. Run MOJO Inference
- Predict class and probabilities.
- Example:  
  - `google.com` → Class: `benign`, Probabilities: `{'benign': 0.95, 'malicious': 0.05}`

#### c. Generate SHAP Explanation
- Computes feature contributions for the prediction.
- Example:
  ```
  length: -0.02
  entropy: 0.15
  num_dots: -0.01
  num_hyphens: 0.00
  num_digits: -0.05
  ```

#### d. Generate AI Playbook
- SHAP explanation sent to Gemini AI API.
- Returns a step-by-step incident response playbook:
  ```
  1. Block the domain at firewall level.
  2. Monitor DNS traffic for related activity.
  3. Alert SOC for further investigation.
  ```

#### e. Save to Domain-Specific Markdown File
- Filename format: `PLAYBOOK_<sanitized_domain>.md`
- Examples:
  - `PLAYBOOK_google_com.md`
  - `PLAYBOOK_sdjhskdh_com.md`

---

## 3. Flow Diagram

```
+-------------------+
| Command:          |
| python 6_test_domain.py google.com sdjhskdh.com
+-------------------+
          |
          v
+-------------------+
| H2O Initialization|
+-------------------+
          |
          v
+-------------------+
| Load MOJO Model   |
| model/DGA_Leader.zip
+-------------------+
          |
          v
+-------------------+
| For each domain:  |
| 1. Featurize      |
| 2. MOJO Prediction|
| 3. SHAP Analysis  |
| 4. Generate AI    |
|    Playbook       |
| 5. Save Markdown  |
+-------------------+
          |
          v
+-------------------+
| Output files:     |
| PLAYBOOK_google_com.md
| PLAYBOOK_sdjhskdh_com.md
+-------------------+
```

---

## 4. Output Files

| Domain          | Output File                  |
|-----------------|------------------------------|
| google.com      | PLAYBOOK_google_com.md       |
| sdjhskdh.com    | PLAYBOOK_sdjhskdh_com.md    |

---

This workflow ensures that **each domain gets a self-contained playbook** including:

- Prediction class and probabilities
- SHAP explanation of model reasoning
- AI-generated step-by-step incident response plan

