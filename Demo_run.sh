                                                                             
#!/usr/bin/env bash
# run_demo.sh - simple, reliable demo runner

set -e

# Activate venv if present
if [ -f "venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
fi

# Run simulator (script prints and writes outputs/results.csv)
python src/simulator.py

# Ensure headless plotting works in environments with no display
export MPLBACKEND=Agg

# Run visualizer
python src/visualize.py

echo "Demo finished. Results: outputs/results.csv and outputs/crack_plot.png"




