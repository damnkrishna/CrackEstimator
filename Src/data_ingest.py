# src/data_ingest.py
import pandas as pd

def load_passwords(path: str):
    df = pd.read_csv(path, header=None, names=['password'])
    # drop empties and duplicates for cleanliness
    df = df.dropna().drop_duplicates().reset_index(drop=True)
    return df

if __name__ == '__main__':
    print(load_passwords('data/synthetic_passwords.txt'))
                                                           
