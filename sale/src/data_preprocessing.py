import pandas as pd

def load_data(filepath):
    """Load sales data from a CSV file."""
    return pd.read_csv(filepath)

def clean_data(df):
    """Basic data cleaning: drop NA, reset index."""
    df = df.dropna().reset_index(drop=True)
    return df 