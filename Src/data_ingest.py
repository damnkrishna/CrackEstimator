# src/data_ingest.py
import pandas as pd
from pathlib import Path

def load_passwords(path: str) -> pd.DataFrame:
    """
    Load passwords from a text or CSV file into a pandas DataFrame.
    Returns DataFrame with at least a 'password' column.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"{path} does not exist")

    if path_obj.suffix == ".txt":
        df = pd.read_csv(path, header=None, names=['password'])
    elif path_obj.suffix == ".csv":
        df = pd.read_csv(path)
        if 'password' not in df.columns:
            raise ValueError("CSV must have a 'password' column")
    else:
        raise ValueError("Unsupported file type. Use .txt or .csv")

    # Clean passwords
    df['password'] = df['password'].astype(str).str.strip()
    df.drop_duplicates(subset=['password'], inplace=True)
    df = df[df['password'] != '']  # remove empty passwords
    return df

if __name__ == "__main__":
    # Quick test
    df = load_passwords("data/synthetic_passwords.txt")
    print(f"Loaded {len(df)} passwords")
    print(df.head())
                          
