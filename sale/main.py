from src.data_preprocessing import load_data, clean_data
from src.feature_selection import plot_correlation_heatmap
from src.model_training import train_linear_regression, train_random_forest, train_xgboost, evaluate_model
from src.utils import split_data

import pandas as pd

if __name__ == "__main__":
    # Load and clean data
    df = load_data('data/sales_data.csv')
    df = clean_data(df)

    # Plot correlation heatmap
    plot_correlation_heatmap(df)

    # Feature selection (example: use all columns except 'sales' as features)
    features = [col for col in df.columns if col != 'sales']
    X = df[features]
    y = df['sales']

    # Split data
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Train models
    lr_model = train_linear_regression(X_train, y_train)
    rf_model = train_random_forest(X_train, y_train)
    xgb_model = train_xgboost(X_train, y_train)

    # Evaluate models
    print('Linear Regression:', evaluate_model(lr_model, X_test, y_test))
    print('Random Forest:', evaluate_model(rf_model, X_test, y_test))
    print('XGBoost:', evaluate_model(xgb_model, X_test, y_test)) 