# src/policy_engine.py
import re
from typing import Dict, Any

DEFAULT_POLICY = {
    'min_length': 8,
    'require_upper': True,
    'require_lower': True,
    'require_digit': True,
    'require_symbol': False,
    'blacklist': ['password', '123456', 'qwerty']
}

class PolicyEngine:
    def __init__(self, policy: Dict[str, Any] = None):
        self.policy = policy or DEFAULT_POLICY

    def check(self, pwd: str) -> Dict[str, Any]:
        p = self.policy
        result = {'password': pwd}
        result['length'] = len(pwd)
        result['has_upper'] = bool(re.search(r'[A-Z]', pwd))
        result['has_lower'] = bool(re.search(r'[a-z]', pwd))
        result['has_digit'] = bool(re.search(r'\d', pwd))
        result['has_symbol'] = bool(re.search(r'[^A-Za-z0-9]', pwd))
        result['blacklisted'] = any(b in pwd.lower() for b in p.get('blacklist', []))

        # policy pass/fail
        ok = True
        if result['length'] < p['min_length']:
            ok = False
        if p['require_upper'] and not result['has_upper']:
            ok = False
        if p['require_lower'] and not result['has_lower']:
            ok = False
        if p['require_digit'] and not result['has_digit']:
            ok = False
        if p['require_symbol'] and not result['has_symbol']:
            ok = False
        if result['blacklisted']:
            ok = False
        result['policy_ok'] = ok
        return result

if __name__ == '__main__':
    pe = PolicyEngine()
    print(pe.check('P@ssw0rd'))
