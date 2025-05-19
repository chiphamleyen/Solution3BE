import pandas as pd
import numpy as np
import tensorflow as tf
from urllib.parse import urlparse
from sklearn.preprocessing import LabelEncoder
from tf_keras.models import load_model

import re
import socket

def label_decoder(label):
    if label == 0:
        return "Benign"
    elif label == 1:
        return "Defacement"
    elif label == 2:
        return "Malware"
    elif label == 3:
        return "Phishing"

def detection_decoder(label):
    if label == "Benign":
        return False
    else:
        return True

def get_prediction(
        dll_df: pd.DataFrame, 
        pe_header_df: pd.DataFrame, 
        pe_section_df: pd.DataFrame,
        api_function_df: pd.DataFrame,
    ) -> pd.DataFrame:
    # Load models
    model = load_model('/ml_models/best_hybrid_malware_model.keras')    
    # Create result df
    result_df = pd.DataFrame(columns=["url", "detection", "classifier"])
    result_df['url'] = dll_df['url']
    result_df['classifier'] = dll_df
    
    for i in range(len(result_df)):
        classifier = label_decoder(result_df.loc[i, 'classifier'])
        detection = detection_decoder(classifier)
        result_df.loc[i, 'classifier'] = classifier
        result_df.loc[i, 'detection'] = detection

    return result_df