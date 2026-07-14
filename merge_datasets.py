"""
Job Scam Detector — Step 5: Merge EMSCAD + Hand-Authored Modern Examples
Combines the large historical EMSCAD dataset with the small, hand-authored
modern scam/legit set into one unified file for the rule-based + ML layers.
A 'source' column tracks where each row came from, since the two sets have
very different characteristics (volume vs. recency) and you may want to
weight or evaluate them separately later.
"""

import json
import pandas as pd

EMSCAD_PATH = "data/cleaned_postings.csv"
MODERN_PATH = "data/modern_scam_examples.json"
OUTPUT_PATH = "data/combined_dataset.csv"


def load_emscad():
    df = pd.read_csv(EMSCAD_PATH)
    out = pd.DataFrame({
        "text": df["full_text"],
        "fraudulent": df["fraudulent"],
        "source": "emscad",
        "category": "unlabeled",  # EMSCAD has no archetype label
    })
    return out


def load_modern():
    with open(MODERN_PATH) as f:
        examples = json.load(f)
    out = pd.DataFrame({
        "text": [ex["text"] for ex in examples],
        "fraudulent": [ex["label"] for ex in examples],
        "source": "hand_authored",
        "category": [ex["category"] for ex in examples],
    })
    return out


def main():
    print("Loading EMSCAD ...")
    emscad_df = load_emscad()
    print(f"  {len(emscad_df):,} rows "
          f"({emscad_df['fraudulent'].sum()} fraud / {(emscad_df['fraudulent']==0).sum()} legit)")

    print("Loading hand-authored modern examples ...")
    modern_df = load_modern()
    print(f"  {len(modern_df):,} rows "
          f"({modern_df['fraudulent'].sum()} fraud / {(modern_df['fraudulent']==0).sum()} legit)")

    combined = pd.concat([emscad_df, modern_df], ignore_index=True)

    # Drop any empty text rows before saving
    combined = combined[combined["text"].str.strip().str.len() > 0]

    combined.to_csv(OUTPUT_PATH, index=False)

    print(f"\nSaved combined dataset -> {OUTPUT_PATH}")
    print(f"Total rows: {len(combined):,}")
    print(f"Fraud: {combined['fraudulent'].sum():,} | Legit: {(combined['fraudulent']==0).sum():,}")
    print(f"\nBreakdown by source:")
    print(combined.groupby(["source", "fraudulent"]).size())


if __name__ == "__main__":
    main()
