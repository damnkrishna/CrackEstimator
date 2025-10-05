#!/usr/bin/env bash
source venv/bin/activate
python -c "from src.data_ingest import load_passwords; import pandas as pd; pw=load_passwords('data/synthetic_passwords.txt')['password']; from src.simulator import run_simulation; df=run_simulation(pw); df.to_csv('outputs/results.csv', index=False); print('results saved');"
python -c "from src.visualize import plot_cumulative; import pandas as pd; df=pd.read_csv('outputs/results.csv'); plot_cumulative(df)"
