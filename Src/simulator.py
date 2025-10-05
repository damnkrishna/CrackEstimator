# src/simulator.py
"""
Phase 3-ready simulator (drop-in replacement for your old simulator.py).

Features:
- Uses src.policy_engine.PolicyEngine for policy checks (check_password).
- Optionally loads a small wordlist from data/rockyou-subset.txt for dictionary checks.
- Performs a small set of mangling variants (leet, digit suffix/prefix, symbol) for fast dictionary hits.
- Resilient imports so it runs from project root or inside src/.
- Produces outputs/results.csv when run as a script.
"""
import math
from pathlib import Path
from typing import Iterable, List, Set, Dict
import pandas as pd
from tqdm import tqdm

# resilient imports (works from project root or inside src/)
try:
    from src.policy_engine import PolicyEngine
    from src.attacker_models import ALL_PROFILES
except Exception:
    from policy_engine import PolicyEngine  # type: ignore
    from attacker_models import ALL_PROFILES  # type: ignore


# ------------------ Mangling helpers (small, fast) ------------------
def leet_variants(word: str) -> Set[str]:
    mapping = {"a": "@", "o": "0", "i": "1", "e": "3", "s": "5"}
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    for i, ch in enumerate(word):
        r = mapping.get(ch.lower())
        if r:
            variants.add(word[:i] + r + word[i+1:])
    return variants


def digit_variants(word: str, max_len: int = 2) -> Set[str]:
    variants = set()
    samples = ["1", "12", "123", "01", "07", "42", "99"]
    for s in samples:
        if 1 <= len(s) <= max_len:
            variants.add(word + s)
            variants.add(s + word)
    return variants


def symbol_variants(word: str, symbols: List[str] = None) -> Set[str]:
    if symbols is None:
        symbols = ["!", "@", "#", "$"]
    out = set()
    for s in symbols:
        out.add(word + s)
        out.add(s + word)
    return out


def generate_mangled_set(base: str) -> Set[str]:
    out = set()
    out.update(leet_variants(base))
    out.update(digit_variants(base))
    out.update(symbol_variants(base))
    # keep base forms too
    out.add(base)
    out.add(base.lower())
    return out


# ------------------ Entropy & time estimation ------------------
def estimate_entropy(pwd: str) -> float:
    pool = 0
    if any("a" <= c <= "z" for c in pwd):
        pool += 26
    if any("A" <= c <= "Z" for c in pwd):
        pool += 26
    if any(c.isdigit() for c in pwd):
        pool += 10
    if any(not c.isalnum() for c in pwd):
        pool += 32
    if pool == 0:
        return 0.0
    return len(pwd) * math.log2(pool)


def time_to_bruteforce_seconds(entropy_bits: float, hash_rate: float) -> float:
    if hash_rate <= 0:
        return float("inf")
    attempts = 2 ** entropy_bits
    avg_attempts = attempts / 2.0
    return avg_attempts / float(hash_rate)


# ------------------ Simulator (Phase 3) ------------------
class Simulator:
    def __init__(self, wordlist_path: str = "data/rockyou-subset.txt", mangle_limit: int = 2000):
        """
        wordlist_path: optional small wordlist (keep subset for performance).
        mangle_limit: how many top words to expand with mangling (to limit memory/time).
        """
        self.pe = PolicyEngine()
        self.wordlist_path = Path(wordlist_path)
        self.use_wordlist = self.wordlist_path.exists()
        self.wordlist_set: Set[str] = set()
        self.mangle_index: Dict[str, str] = {}  # mangled -> base
        self.mangle_limit = int(mangle_limit)
        if self.use_wordlist:
            self._load_wordlist()

    def _load_wordlist(self):
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
                words = [w.strip() for w in fh if w.strip()]
        except Exception:
            words = []
        words = [w for w in words if w]  # filter empties
        # store lowercase for case-insensitive checks
        self.wordlist_set = set(w.lower() for w in words)
        limit = min(len(words), self.mangle_limit)
        for base in words[:limit]:
            for v in generate_mangled_set(base):
                self.mangle_index[v.lower()] = base.lower()

    def _is_wordlist_or_mangled(self, pwd: str) -> bool:
        pl = pwd.lower()
        if pl in self.wordlist_set:
            return True
        if pl in self.mangle_index:
            return True
        # attempt simple reverse-leet to catch common variations
        rev = pl.replace("0", "o").replace("@", "a").replace("1", "i").replace("3", "e").replace("5", "s")
        if rev in self.wordlist_set:
            return True
        return False

    def run(self, passwords: Iterable[str], limit: int = None) -> pd.DataFrame:
        pw_list = list(passwords)
        if limit is not None:
            pw_list = pw_list[:limit]

        rows = []
        for pwd in tqdm(pw_list, desc="Simulating"):
            pwd = str(pwd)
            info = self.pe.check_password(pwd)
            entropy = estimate_entropy(pwd)

            for attacker in ALL_PROFILES:
                # Dictionary model:
                dict_hit = False
                if self.use_wordlist:
                    # casual attacker uses top-small subset heuristics
                    if attacker.name.lower() == "casual":
                        # quick top-N check (cheap): check membership in small slice
                        top_small = set(list(self.wordlist_set)[:200])
                        dict_hit = (pwd.lower() in top_small) or self._is_wordlist_or_mangled(pwd)
                    else:
                        dict_hit = self._is_wordlist_or_mangled(pwd)
                else:
                    # fallback heuristic
                    dict_hit = (pwd.lower() in ["password", "123456", "qwerty"] or len(pwd) <= 6)

                t_dict = 1.0 if dict_hit else float("inf")
                t_bruteforce = time_to_bruteforce_seconds(entropy, attacker.hash_rate)
                # cap by attacker's max attempts
                max_seconds = attacker.brute_force_max_attempts / attacker.hash_rate if attacker.hash_rate > 0 else float("inf")
                if t_bruteforce > max_seconds:
                    t_bruteforce = float("inf")

                rows.append({
                    "password": pwd,
                    "policy_ok": bool(info.get("policy_ok", False)),
                    "attacker": attacker.name,
                    "dict_time_sec": t_dict,
                    "bruteforce_time_sec": t_bruteforce,
                    "entropy_bits": entropy
                })

        return pd.DataFrame(rows)


# ------------------ Script entrypoint ------------------
if __name__ == "__main__":
    # prefer Phase 1 loader when available
    try:
        from src.data_ingest import load_passwords  # type: ignore
    except Exception:
        try:
            from data_ingest import load_passwords  # type: ignore
        except Exception:
            load_passwords = None

    if load_passwords:
        pw_df = load_passwords("data/synthetic_passwords.txt")
        pw_series = pw_df["password"]
    else:
        # fallback: direct read
        pw_series = pd.read_csv("data/synthetic_passwords.txt", header=None, names=["password"])["password"]

    sim = Simulator()
    df = sim.run(pw_series)
    df.to_csv("outputs/results.csv", index=False)
    print("Saved outputs/results.csv — rows:", len(df))
