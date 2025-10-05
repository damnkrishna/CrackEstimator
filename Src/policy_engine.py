# src/policy_engine.py
import re
from typing import Dict, Any, Iterable, List, Optional
from pathlib import Path
import pandas as pd

DEFAULT_POLICY: Dict[str, Any] = {
    "min_length": 8,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": False,
    # blacklist can be either a list or a path to a file (string)
    "blacklist": ["password", "123456", "qwerty"]
}


class PolicyEngine:
    """
    PolicyEngine checks passwords against a configurable policy.
    - policy may include 'blacklist' as list[str] or path to a file containing one blacklisted
      password per line.
    """

    def __init__(self, policy: Optional[Dict[str, Any]] = None):
        self.policy = (policy.copy() if policy else DEFAULT_POLICY.copy())
        # normalize blacklist into a set for fast checks
        bl = self.policy.get("blacklist", [])
        if isinstance(bl, (str, Path)):
            bl_path = Path(bl)
            if bl_path.exists():
                with open(bl_path, "r", encoding="utf-8") as fh:
                    items = [line.strip() for line in fh if line.strip()]
            else:
                items = []
        elif isinstance(bl, Iterable):
            items = list(bl)
        else:
            items = []
        # store lowercase forms for case-insensitive blacklist checks
        self.blacklist = set(x.lower() for x in items)

    def check_password(self, password: str) -> Dict[str, Any]:
        """
        Check a single password and return a dictionary of results.
        Fields:
          - password: original string
          - length: int
          - min_length: bool
          - has_upper, has_lower, has_digit, has_symbol: bool
          - blacklisted: bool (True if NOT blacklisted - i.e. passes blacklist check)
          - policy_ok: bool overall
        """
        p = self.policy
        pwd = password or ""
        res: Dict[str, Any] = {}
        res["password"] = pwd
        res["length"] = len(pwd)
        res["min_length"] = res["length"] >= int(p.get("min_length", 0))

        # pattern checks (only enforced if policy asks for them)
        res["has_upper"] = bool(re.search(r"[A-Z]", pwd))
        res["has_lower"] = bool(re.search(r"[a-z]", pwd))
        res["has_digit"] = bool(re.search(r"\d", pwd))
        # consider common printable symbols; this is adjustable
        res["has_symbol"] = bool(re.search(r"[!@#$%^&*()\-\_\+=\[\]{};:'\",.<>/?\\|`~]", pwd))

        # blacklist: pass if password (lowercased) is NOT in blacklist
        res["blacklist_ok"] = (pwd.lower() not in self.blacklist)

        # Apply policy rules (if a rule is not required, treat it as True)
        ok = True
        if p.get("require_upper", False) and not res["has_upper"]:
            ok = False
        if p.get("require_lower", False) and not res["has_lower"]:
            ok = False
        if p.get("require_digit", False) and not res["has_digit"]:
            ok = False
        if p.get("require_symbol", False) and not res["has_symbol"]:
            ok = False
        if not res["min_length"]:
            ok = False
        if not res["blacklist_ok"]:
            ok = False

        res["policy_ok"] = ok
        return res

    def audit_passwords(self, passwords: Iterable[str]) -> pd.DataFrame:
        """
        Audit an iterable of password strings and return a DataFrame with results.
        The returned columns are:
        ['password','length','min_length','has_upper','has_lower','has_digit',
         'has_symbol','blacklist_ok','policy_ok']
        """
        records: List[Dict[str, Any]] = []
        for pwd in passwords:
            records.append(self.check_password(pwd))
        df = pd.DataFrame.from_records(records)
        # ensure column order
        cols = [
            "password",
            "length",
            "min_length",
            "has_upper",
            "has_lower",
            "has_digit",
            "has_symbol",
            "blacklist_ok",
            "policy_ok",
        ]
        # add any missing columns (defensive)
        for c in cols:
            if c not in df.columns:
                df[c] = None
        return df[cols]


# CLI for quick testing and demonstration
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="PolicyEngine quick test / audit")
    parser.add_argument(
        "input",
        nargs="?",
        default="data/synthetic_passwords.txt",
        help="Path to passwords file (.txt with one password per line, or .csv with 'password' column)",
    )
    parser.add_argument(
        "--blacklist",
        "-b",
        default=None,
        help="Optional blacklist file (one entry per line) or comma-separated list",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=None,
        help="Override default min length for quick test",
    )
    args = parser.parse_args()

    # load passwords using local data loader if available (works whether run from project root or src/)
    try:
        # prefer src.data_ingest when running from project root
        from src.data_ingest import load_passwords  # type: ignore
    except Exception:
        try:
            from data_ingest import load_passwords  # type: ignore
        except Exception:
            load_passwords = None

    pw_path = Path(args.input)
    if load_passwords:
        try:
            df_pw = load_passwords(str(pw_path))
            pw_series = df_pw["password"]
        except Exception as e:
            print("load_passwords helper failed:", e, file=sys.stderr)
            # fallback: try to read as simple txt list
            if pw_path.exists():
                with open(pw_path, "r", encoding="utf-8") as fh:
                    pw_series = pd.Series([line.strip() for line in fh if line.strip()])
            else:
                print(f"File not found: {pw_path}", file=sys.stderr)
                sys.exit(2)
    else:
        # fallback: simple txt loader
        if pw_path.exists():
            with open(pw_path, "r", encoding="utf-8") as fh:
                pw_series = pd.Series([line.strip() for line in fh if line.strip()])
        else:
            print(f"Password file not found: {pw_path}", file=sys.stderr)
            sys.exit(2)

    # build policy override if requested
    policy = {}
    if args.min_length is not None:
        policy["min_length"] = args.min_length
    if args.blacklist:
        # accept comma-separated quick list or path to file
        bl = args.blacklist
        if "," in bl:
            policy["blacklist"] = [x.strip() for x in bl.split(",") if x.strip()]
        else:
            policy["blacklist"] = bl  # path; PolicyEngine will read file if path exists

    engine = PolicyEngine(policy=policy if policy else None)
    result_df = engine.audit_passwords(pw_series)
    # print summary
    total = len(result_df)
    passed = result_df["policy_ok"].sum()
    print(f"Audited {total} passwords — {passed} passed the policy ({passed/total:.1%})")
    print(result_df.head(10).to_string(index=False))
