# src/simulator.py
import math
import pandas as pd
from tqdm import tqdm

from src.policy_engine import PolicyEngine
from src.attacker_models import ALL_PROFILES

# Rough entropy estimate (very simple):
def estimate_entropy(pwd: str) -> float:
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

def time_to_bruteforce_seconds(entropy_bits: float, hash_rate: float):
    attempts = 2 ** entropy_bits
    avg_attempts = attempts / 2
    return avg_attempts / hash_rate

def run_simulation(passwords: pd.Series):
    pe = PolicyEngine()
    rows = []
    for pwd in tqdm(passwords, desc='Simulating'):
        info = pe.check(pwd)
        entropy = estimate_entropy(pwd)
        info['entropy_bits'] = entropy
        for attacker in ALL_PROFILES:
            dict_success = 1 if pwd.lower() in ['password','123456','qwerty'] or len(pwd) <= 6 else 0
            if dict_success:
                t_dict = 1.0
            else:
                t_dict = float('inf')

            t_bruteforce = time_to_bruteforce_seconds(entropy, attacker.hash_rate)
            max_seconds = attacker.brute_force_max_attempts / attacker.hash_rate
            if t_bruteforce > max_seconds:
                t_bruteforce = float('inf')

            rows.append({
                'password': pwd,
                'policy_ok': info['policy_ok'],
                'attacker': attacker.name,
                'dict_time_sec': t_dict,
                'bruteforce_time_sec': t_bruteforce,
                'entropy_bits': entropy
            })
    return pd.DataFrame(rows)

if __name__ == '__main__':
    pw = pd.read_csv('data/synthetic_passwords.txt', header=None, names=['password'])['password']
    df = run_simulation(pw)
    print(df.head())
    df.to_csv('outputs/results.csv', index=False)
                                                   
