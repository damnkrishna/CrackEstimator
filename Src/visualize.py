# src/visualize.py
import pandas as pd
import matplotlib.pyplot as plt

def plot_cumulative(df: pd.DataFrame, output_path='outputs/crack_plot.png'):
    thresholds = {
        '1_min': 60,
        '1_hour': 3600,
        '1_day': 86400,
        '1_year': 86400*365,
        '100_years': 86400*365*100
    }
    fig, ax = plt.subplots()
    attackers = df['attacker'].unique()
    for attacker in attackers:
        sub = df[df['attacker'] == attacker]
        frac = []
        for tname, sec in thresholds.items():
            cracked = ((sub['bruteforce_time_sec'] <= sec) | (sub['dict_time_sec'] <= sec)).sum()
            frac.append(cracked / len(sub))
        ax.plot(list(thresholds.keys()), frac, label=attacker)
    ax.set_ylabel('Fraction cracked')
    ax.set_title('Fraction of passwords cracked by attacker over thresholds')
    ax.legend()
    fig.savefig(output_path, bbox_inches='tight')
    print('Saved plot to', output_path)

if __name__ == '__main__':
    df = pd.read_csv('outputs/results.csv')
    plot_cumulative(df)
