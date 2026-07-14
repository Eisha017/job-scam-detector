"""
Job Scam Detector — Step 2: Data Cleaning & Feature Engineering
Loads the raw EMSCAD dataset, strips HTML from text fields, engineers
missingness-based red-flag features, and saves a cleaned CSV ready for
the rule-based + ML layers.
"""

import pandas as pd
from bs4 import BeautifulSoup

INPUT_PATH = "data/DataSet.csv"
OUTPUT_PATH = "data/cleaned_postings.csv"


def strip_html(text):
    """Remove HTML tags and normalize whitespace in a text field."""
    if pd.isna(text):
        return ""
    soup = BeautifulSoup(str(text), "html.parser")
    clean = soup.get_text(separator=" ")
    return " ".join(clean.split())


def engineer_features(df):
    """Add boolean/derived features. Missingness itself is a signal,
    so we capture 'was this field present?' before cleaning the text."""

    df["has_salary_range"] = df["salary_range"].notna().astype(int)
    df["has_department"] = df["department"].notna().astype(int)
    df["has_benefits_text"] = df["benefits"].notna().astype(int)
    df["has_company_profile"] = df["company_profile"].notna().astype(int)

    # telecommuting / has_company_logo / has_questions are already t/f -> convert to 0/1
    for col in ["telecommuting", "has_company_logo", "has_questions"]:
        df[col] = df[col].map({"t": 1, "f": 0, True: 1, False: 0}).fillna(0).astype(int)

    # Combine all text fields into one searchable blob for rule-based detectors later
    text_cols = ["title", "company_profile", "description", "requirements", "benefits"]
    df["full_text"] = df[text_cols].apply(
        lambda row: " ".join(str(v) for v in row if pd.notna(v)), axis=1
    )

    return df


def main():
    print(f"Loading raw data from {INPUT_PATH} ...")
    df = pd.read_csv(INPUT_PATH)
    print(f"Loaded {len(df):,} rows, {df.shape[1]} columns")

    # Clean HTML out of the main text fields
    print("Stripping HTML from text fields ...")
    for col in ["company_profile", "description", "requirements", "benefits"]:
        df[col + "_clean"] = df[col].apply(strip_html)

    # Rebuild full_text from CLEANED versions (do this after stripping, not before)
    print("Engineering features ...")
    df = engineer_features(df)
    clean_text_cols = [
        "title",
        "company_profile_clean",
        "description_clean",
        "requirements_clean",
        "benefits_clean",
    ]
    df["full_text"] = df[clean_text_cols].apply(
        lambda row: " ".join(str(v) for v in row if pd.notna(v) and v != ""), axis=1
    )

    # Normalize label to int (t/f -> 1/0)
    df["fraudulent"] = df["fraudulent"].map({"t": 1, "f": 0, True: 1, False: 0})

    # Keep a clean, focused set of columns for the next steps
    keep_cols = [
        "title",
        "location",
        "department",
        "company_profile_clean",
        "description_clean",
        "requirements_clean",
        "benefits_clean",
        "full_text",
        "has_salary_range",
        "has_department",
        "has_benefits_text",
        "has_company_profile",
        "telecommuting",
        "has_company_logo",
        "has_questions",
        "employment_type",
        "required_experience",
        "required_education",
        "industry",
        "fraudulent",
    ]
    out_df = df[keep_cols]

    out_df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved cleaned dataset to {OUTPUT_PATH}")
    print(f"Shape: {out_df.shape}")
    print(f"Fraud label distribution:\n{out_df['fraudulent'].value_counts()}")
    print(f"\nSample full_text (first 300 chars):\n{out_df['full_text'].iloc[0][:300]}")


if __name__ == "__main__":
    main()
