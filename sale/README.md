# Sales Forecasting using Machine Learning

## Tech Stack
- Scikit-learn
- XGBoost
- Pandas
- Matplotlib
- Seaborn

## Project Overview
This project forecasts retail sales using machine learning models. It includes feature selection, correlation analysis, regression models (Linear, Random Forest, XGBoost), and model tuning/validation.

## Project Structure
```
.
├── data/
│   └── sales_data.csv
├── notebooks/
│   └── eda_and_modeling.ipynb
├── src/
│   ├── data_preprocessing.py
│   ├── feature_selection.py
│   ├── model_training.py
│   └── utils.py
├── main.py
├── requirements.txt
└── README.md
```

## Usage
1. Place your sales data in the `data/` folder as `sales_data.csv`.
2. Run the notebook in `notebooks/` for EDA and modeling.
3. Use `main.py` to execute the full pipeline.

## Installation
```bash
pip install -r requirements.txt
``` 