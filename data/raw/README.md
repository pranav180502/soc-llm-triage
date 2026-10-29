# Raw dataset (not included)

The CICIDS2017 CSV files are about 1.2 GB, so they are not stored in this repository.

1. Download **GeneratedLabelledFlows.zip** (CICIDS2017) from the Canadian Institute for Cybersecurity:
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract it so the CSV files are in `data/raw/cicids2017/TrafficLabelling/`.
3. Run `python src/converter.py`.

The processed alerts used in the midterm are already included in `data/clean/` and `data/poisoned/`.
