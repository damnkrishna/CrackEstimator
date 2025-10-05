# CrackEstimator
Simulate, evaluate, and visualize password policy effectiveness.

## **Project Overview**

Python-based tool that evaluates password policies by simulating attacker success and estimating the time required to crack passwords under different scenarios. It combines synthetic or public password datasets with configurable attacker models (casual, skilled, state-level) to produce reproducible, ethical, and educational insights into password security.

---

## **Key Features**

* **Policy Engine:** Checks passwords against rules like length, complexity, character requirements, and blacklist.
* **Attacker Simulation:** Models dictionary attacks, mangling, and brute-force attempts using different attacker profiles.
* **Time-to-Crack Estimation:** Provides approximate cracking times based on password entropy and attacker capabilities.
* **Visualizations:** Generates heatmaps and cumulative cracking plots for easy comparison of policy strength across attacker types.
* **Ethical & Educational:** Uses only synthetic or public datasets; no real accounts or live cracking.

---

## **Applications**

* Cybersecurity education and training for students or organizations.
* Policy evaluation for IT administrators and security teams.
* Awareness-building for users about weak passwords and common pitfalls.
* Research demonstrations of attacker modeling and entropy-based risk assessment.

---

## **Deliverables**

* Python source code (`src/`)
* Sample synthetic password datasets (`data/`)
* Results CSV and visualizations (`outputs/`)
* Demo script (`run_demo.sh`) to run full simulation
* Optional report generation (HTML/PDF)
* Documentation of each project phase

---

## **Phase-wise Progress**

### **Phase 0 – Project Setup & Demo Pipeline**

* Project repo and structure initialized (`src/`, `data/`, `outputs/`)
* Virtual environment created and dependencies installed (`pandas`, `numpy`, `matplotlib`, `tqdm`)
* Starter source files and synthetic password dataset added
* `run_demo.sh` created and tested
* Verified end-to-end demo pipeline: simulation → results CSV → plot
* Fixes: indentation errors and import paths resolved
* Output generated:

  * `outputs/results.csv`
  * `outputs/crack_plot.png`

**Goal:** Confirm environment and pipeline work reproducibly.

---

### **Phase 1 – Data Ingestion**

* Load passwords from `.txt` or `.csv` files
* Clean and validate passwords (remove empty/duplicate entries)
* Optional: synthetic dataset generation for testing purposes
* CLI test to quickly verify data loading

**Goal:** Prepare clean, structured password data for simulation.

---

### **Phase 2 – Policy Engine**

* Enforce password policies:

  * Minimum length
  * Uppercase/lowercase letters
  * Digits & symbols
  * Blacklist checks
* Check each password against defined rules
* Output: detailed per-password compliance metrics

---

### **Phase 3 – Attacker Models**

* Define attacker profiles: casual, skilled, state-level
* Attributes per profile:

  * Dictionary size
  * Hash rate (guesses/sec)
  * Maximum brute-force attempts
* Prepare for simulation of attack strategies

---

### **Phase 4 – Simulation Engine**

* Estimate **time-to-crack** per password using:

  * Dictionary lookup
  * Brute-force entropy model
* Integrate attacker profiles with policy engine output
* Save results in `outputs/results.csv`

---

### **Phase 5 – Visualization & Reporting**

* Generate plots:

  * Cumulative cracked passwords vs. time
  * Heatmaps of policy effectiveness
* Save visualizations (`outputs/crack_plot.png`)
* Optional: HTML/PDF report generation for presentations

---

### **Phase 6 – Documentation & Demo**

* Full README with phase explanations and setup instructions
* Ethics statement emphasizing educational and safe usage
* Demo video showcasing tool workflow (optional)
* Example report with findings and recommendations

---

## **Installation & Setup**

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/password-audit.git
cd password-audit
```

2. Create a virtual environment and activate:

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the demo:

```bash
chmod +x run_demo.sh
./run_demo.sh
```

5. Check outputs:

```bash
ls outputs/
# results.csv
# crack_plot.png
```

---

## **Usage**

**Load custom password file for simulation:**

```python
from src.data_ingest import load_passwords
from src.simulator import run_simulation

pw_df = load_passwords("data/your_password_file.txt")
results = run_simulation(pw_df['password'])
results.to_csv("outputs/custom_results.csv", index=False)
```

**Visualize results:**

```python
from src.visualize import plot_cumulative
import pandas as pd

df = pd.read_csv("outputs/custom_results.csv")
plot_cumulative(df)
```

---

## **Legal & Ethical Considerations**

* Uses only synthetic or publicly available password datasets
* No real accounts or live cracking involved
* Estimates are educational, research-only, and fully reproducible

---

## **References**

* [SecLists](https://github.com/danielmiessler/SecLists)
* RockYou password dataset (sanitized subsets)
* Bonneau et al., “The Quest to Replace Passwords,” IEEE S&P, 2012
* Weir et al., “Testing Metrics for Password Creation Policies,” CCS, 2010
* NIST SP 800-63B Digital Identity Guidelines


### Done till phase 3
