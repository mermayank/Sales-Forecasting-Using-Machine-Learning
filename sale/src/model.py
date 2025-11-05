from sklearn.linear_model import LinearRegression, Ridge, Lasso, ElasticNet
from sklearn.ensemble import RandomForestRegressor
from xgboost import XGBRegressor
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import pandas as pd
import numpy as np

def train_linear_regression(X_train, y_train):
    """Train a Linear Regression model."""
    model = LinearRegression()
    model.fit(X_train, y_train)
    return model

def train_ridge_regression(X_train, y_train):
    """Train a Ridge Regression model."""
    model = Ridge()
    model.fit(X_train, y_train)
    return model

def train_lasso_regression(X_train, y_train):
    """Train a Lasso Regression model."""
    model = Lasso()
    model.fit(X_train, y_train)
    return model

def train_elasticnet_regression(X_train, y_train):
    """Train an ElasticNet Regression model."""
    model = ElasticNet()
    model.fit(X_train, y_train)
    return model

def train_random_forest(X_train, y_train):
    """Train a Random Forest Regressor."""
    model = RandomForestRegressor(random_state=42)
    model.fit(X_train, y_train)
    return model

def train_xgboost(X_train, y_train):
    """Train an XGBoost Regressor."""
    model = XGBRegressor(random_state=42)
    model.fit(X_train, y_train)
    return model

def predict_sales(model, input_data):
    """Make sales predictions using the trained model."""
    if isinstance(input_data, dict):
        # Convert dict to DataFrame
        input_df = pd.DataFrame([input_data])
    elif isinstance(input_data, pd.DataFrame):
        input_df = input_data
    else:
        input_df = pd.DataFrame(input_data)
    
    prediction = model.predict(input_df)
    return prediction[0] if len(prediction) == 1 else prediction

def evaluate_model(model, X_test, y_test):
    """Evaluate a regression model and return comprehensive metrics."""
    y_pred = model.predict(X_test)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    return {
        'rmse': rmse,
        'mae': mae,
        'r2_score': r2,
        'predictions': y_pred,
        'actual': y_test
    }

def get_feature_importance(model, feature_names):
    """Get feature importance for tree-based models."""
    if hasattr(model, 'feature_importances_'):
        importance = model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False)
        return feature_importance_df
    else:
        return None

def compare_models(models_dict, X_test, y_test):
    """Compare multiple models and return their performance metrics."""
    results = {}
    for name, model in models_dict.items():
        results[name] = evaluate_model(model, X_test, y_test)
    return results 