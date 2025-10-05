# src/attacker_models.py
from dataclasses import dataclass

@dataclass
class AttackerProfile:
    name: str
    dictionary_size: int  # how many guesses attacker will try from a dictionary
    hash_rate: float      # guesses per second for brute force estimation (hashes/sec)
    brute_force_max_attempts: int

# Example profiles
CASUAL = AttackerProfile('casual', dictionary_size=10000, hash_rate=1e3, brute_force_max_attempts=10**8)
SKILLED = AttackerProfile('skilled', dictionary_size=10**6, hash_rate=1e6, brute_force_max_attempts=10**10)
STATE = AttackerProfile('state', dictionary_size=10**8, hash_rate=1e9, brute_force_max_attempts=10**12)

ALL_PROFILES = [CASUAL, SKILLED, STATE]
