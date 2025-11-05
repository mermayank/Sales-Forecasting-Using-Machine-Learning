from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from src.model import (
    train_linear_regression, train_ridge_regression, train_lasso_regression, train_elasticnet_regression,
    train_random_forest, train_xgboost, predict_sales, evaluate_model, get_feature_importance, compare_models
)
from src.data_preprocessing import clean_data
from src.utils import split_data

app = Flask(__name__)

# Load and prepare data
DATA_PATH = 'data/sales_data.csv'
df = pd.read_csv(DATA_PATH)
df = clean_data(df)
categorical_cols = ['ProductCategory', 'ProductName', 'StoreID', 'City']
df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=True)
features = [col for col in df_encoded.columns if col not in ['InvoiceID', 'Date', 'ProductID', 'CustomerID', 'TotalAmount']]
X = df_encoded[features]
y = df_encoded['TotalAmount']
X_train, X_test, y_train, y_test = split_data(X, y)

# Train models (for demo; in production, load pre-trained models)
lr_model = train_linear_regression(X_train, y_train)
ridge_model = train_ridge_regression(X_train, y_train)
lasso_model = train_lasso_regression(X_train, y_train)
elasticnet_model = train_elasticnet_regression(X_train, y_train)
rf_model = train_random_forest(X_train, y_train)
xgb_model = train_xgboost(X_train, y_train)

# Store models in a dictionary for easy access
models = {
    'Linear Regression': lr_model,
    'Ridge Regression': ridge_model,
    'Lasso Regression': lasso_model,
    'ElasticNet Regression': elasticnet_model,
    'Random Forest': rf_model,
    'XGBoost': xgb_model
}

# For form dropdowns
product_categories = sorted(df['ProductCategory'].unique())
product_names = sorted(df['ProductName'].unique())
stores = sorted(df['StoreID'].unique())
cities = sorted(df['City'].unique())

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    model_used = None
    model_metrics = None
    if request.method == 'POST':
        # Get form data
        quantity = float(request.form['Quantity'])
        price_per_unit = float(request.form['PricePerUnit'])
        product_category = request.form['ProductCategory']
        product_name = request.form['ProductName']
        store_id = request.form['StoreID']
        city = request.form['City']
        model_choice = request.form['model']

        # Build input DataFrame with all columns as in training
        input_dict = {
            'Quantity': [quantity],
            'PricePerUnit': [price_per_unit],
        }
        # Add all possible one-hot columns, set to 0, then set the selected ones to 1
        for col in df_encoded.columns:
            if col.startswith('ProductCategory_'):
                input_dict[col] = [1 if col == f'ProductCategory_{product_category}' else 0]
            if col.startswith('ProductName_'):
                input_dict[col] = [1 if col == f'ProductName_{product_name}' else 0]
            if col.startswith('StoreID_'):
                input_dict[col] = [1 if col == f'StoreID_{store_id}' else 0]
            if col.startswith('City_'):
                input_dict[col] = [1 if col == f'City_{city}' else 0]
        # Ensure all feature columns are present
        for col in features:
            if col not in input_dict:
                input_dict[col] = [0]
        input_df = pd.DataFrame(input_dict)[features]

        # Predict using the selected model
        model = models[model_choice]
        prediction = predict_sales(model, input_df)
        model_used = model_choice
        
        # Get model metrics
        model_metrics = evaluate_model(model, X_test, y_test)
    else:
        quantity = price_per_unit = None
        product_category = product_categories[0]
        product_name = product_names[0]
        store_id = stores[0]
        city = cities[0]
        model_choice = 'Linear Regression'
    return render_template(
        'index.html',
        prediction=prediction,
        model_used=model_used,
        model_metrics=model_metrics,
        product_categories=product_categories,
        product_names=product_names,
        stores=stores,
        cities=cities,
        quantity=quantity,
        price_per_unit=price_per_unit,
        product_category=product_category,
        product_name=product_name,
        store_id=store_id,
        city=city,
        model_choice=model_choice,
        model_options=list(models.keys())
    )

@app.route('/model_comparison')
def model_comparison():
    comparison_results = compare_models(models, X_test, y_test)
    rf_importance = get_feature_importance(rf_model, features)
    xgb_importance = get_feature_importance(xgb_model, features)
    return render_template(
        'model_comparison.html',
        comparison_results=comparison_results,
        rf_importance=rf_importance,
        xgb_importance=xgb_importance,
        features=features
    )

@app.route('/api/predict', methods=['POST'])
def api_predict():
    try:
        data = request.get_json()
        model_choice = data.get('model', 'Linear Regression')
        input_data = data.get('input_data', {})
        model = models[model_choice]
        prediction = predict_sales(model, input_data)
        return jsonify({
            'prediction': float(prediction),
            'model': model_choice,
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 400

if __name__ == '__main__':
    app.run(debug=True) 