# src/simulator.py
"""
Simulation runner: estimate time-to-crack for a list/Series of passwords.

Works whether run as:
  python src/simulator.py
or imported from run scripts that live at project root.
"""
import math
from typing import Iterable
import pandas as pd
from tqdm import tqdm

# Import PolicyEngine and attacker models. Use absolute import (src.*) which is
# consistent when running from project root. If that fails (rare), fall back to local import.
try:
    from src.policy_engine import PolicyEngine
    from src.attacker_models import ALL_PROFILES
except Exception:
    # fallback if running from inside src/
    from policy_engine import PolicyEngine  # type: ignore
    from attacker_models import ALL_PROFILES  # type: ignore


def estimate_entropy(pwd: str) -> float:
    """
    Very simple entropy estimator:
      - adds character pool sizes for lowercase, uppercase, digits, symbols
      - returns length * log2(pool)
    This is intentionally basic and meant for demonstration/education.
    """
    pool = 0
    if any('a' <= c <= 'z' for c in pwd):
        pool += 26
    if any('A' <= c <= 'Z' for c in pwd):
        pool += 26
    if any(c.isdigit() for c in pwd):
        pool += 10
    if any(not c.isalnum() for c in pwd):
        pool += 32
    if pool == 0:
        return 0.0
    return len(pwd) * math.log2(pool)


def time_to_bruteforce_seconds(entropy_bits: float, hash_rate: float) -> float:
    """
    Rough estimate: number of combinations ~= 2^entropy_bits.
    Assume average attacker finds the password halfway through the search.
    Return seconds required at given hash_rate (guesses/sec).
    """
    attempts = 2 ** entropy_bits
    avg_attempts = attempts / 2.0
    return avg_attempts / float(hash_rate)


def run_simulation(passwords: Iterable[str]) -> pd.DataFrame:
    """
    Run the simulation for each password and each attacker profile.
    Returns a DataFrame with columns:
      ['password', 'policy_ok', 'attacker', 'dict_time_sec', 'bruteforce_time_sec', 'entropy_bits']
    """
    pe = PolicyEngine()
    rows = []
    for pwd in tqdm(list(passwords), desc="Simulating"):
        # ensure pwd is a string
        pwd = str(pwd)

        # Use new PolicyEngine API
        info = pe.check_password(pwd)
        entropy = estimate_entropy(pwd)
        info['entropy_bits'] = entropy

        for attacker in ALL_PROFILES:
            # Very simple dictionary heuristic: treat some known weak items or very short passwords as in-dictionary
            dict_success = 1 if (pwd.lower() in ['password', '123456', 'qwerty'] or len(pwd) <= 6) else 0
            t_dict = 1.0 if dict_success else float('inf')

            # brute-force time (seconds)
            t_bruteforce = time_to_bruteforce_seconds(entropy, attacker.hash_rate)

            # cap by attacker's maximum attempts (if attacker has limit)
            max_seconds = attacker.brute_force_max_attempts / attacker.hash_rate if attacker.hash_rate > 0 else float('inf')
            if t_bruteforce > max_seconds:
                t_bruteforce = float('inf')

            rows.append({
                'password': pwd,
                'policy_ok': bool(info.get('policy_ok', False)),
                'attacker': attacker.name,
                'dict_time_sec': t_dict,
                'bruteforce_time_sec': t_bruteforce,
                'entropy_bits': entropy
            })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    # Prefer using the project's data_ingest loader when available so Phase 1 is integrated.
    try:
        # when run from project root
        from src.data_ingest import load_passwords  # type: ignore
    except Exception:
        try:
            # when run from inside src/
            from data_ingest import load_passwords  # type: ignore
        except Exception:
            load_passwords = None

    if load_passwords:
        pw_df = load_passwords('data/synthetic_passwords.txt')
        pw_series = pw_df['password']
    else:
        # fallback: read the text file directly
        pw_series = pd.read_csv('data/synthetic_passwords.txt', header=None, names=['password'])['password']

    df = run_simulation(pw_series)
    print(df.head())
    df.to_csv('outputs/results.csv', index=False)
