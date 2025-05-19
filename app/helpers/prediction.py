import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.saving import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Constants
DLL_VOCAB_SIZE = 5000
MAX_DLL_SEQ_LENGTH = 100
API_VOCAB_SIZE = 10000
MAX_API_SEQ_LENGTH = 300

# Load models
model = load_model('ml_models/best_hybrid_malware_model.keras')   


def label_decoder(label):
    if label == 0:
        return "Benign"
    elif label == 1:
        return "RedLineStealer"
    elif label == 2:
        return "Downloader"
    elif label == 3:
        return "RAT"
    elif label == 4:
        return "BankingTrojan"
    elif label == 5:
        return "SnakeKeyLogger"
    elif label == 6:
        return "Spyware"

def detection_decoder(label):
    if label == "Benign":
        return False
    else:
        return True
    
def process_dll_data(dll_df: pd.DataFrame) -> pd.DataFrame:
    dll_df = dll_df.rename(columns={dll_df.columns[0]: 'ID'})
    dll_feature_cols = [col for col in dll_df.columns if col not in ['ID']]
    dll_df['DLL_Sequence'] = dll_df[dll_feature_cols].fillna('').astype(str).agg(' '.join, axis=1)
    dll_df['DLL_Sequence'] = dll_df['DLL_Sequence'].str.lower().str.replace(r'\.dll', '', regex=True)
    return dll_df[['ID', 'DLL_Sequence']]

def process_pe_header_data(pe_header_df: pd.DataFrame) -> pd.DataFrame:
    pe_header_df = pe_header_df.rename(columns={pe_header_df.columns[0]: 'ID'})
    pe_header_feature_cols = [col for col in pe_header_df.columns if col not in ['ID']]
    processed_df = pd.DataFrame()
    processed_df['ID'] = pe_header_df['ID']
    for original_col in pe_header_feature_cols:
        new_col_name = f"Header_{original_col}"
        processed_df[new_col_name] = pd.to_numeric(pe_header_df[original_col], errors='coerce')
    processed_df = processed_df.fillna(0)
    return processed_df

def process_pe_section_data(pe_section_df: pd.DataFrame) -> pd.DataFrame:
    pe_section_df = pe_section_df.rename(columns={pe_section_df.columns[0]: 'ID'})
    pe_section_feature_cols = [col for col in pe_section_df.columns if col not in ['ID']]
    processed_df = pd.DataFrame()
    processed_df['ID'] = pe_section_df['ID']
    for original_col in pe_section_feature_cols:
        new_col_name = f"Sections_{original_col}"
        processed_df[new_col_name] = pd.to_numeric(pe_section_df[original_col], errors='coerce')
    processed_df = processed_df.fillna(0)
    return processed_df

def process_api_function_data(api_function_df: pd.DataFrame) -> pd.DataFrame:
    api_function_df = api_function_df.rename(columns={api_function_df.columns[0]: 'ID'})
    api_function_feature_cols = [col for col in api_function_df.columns if col not in ['ID']]
    api_function_df['API_Sequence'] = api_function_df[api_function_feature_cols].fillna('').astype(str).agg(' '.join, axis=1)
    api_function_df['API_Sequence'] = api_function_df['API_Sequence'].str.lower()
    return api_function_df[['ID', 'API_Sequence']]

def get_prediction(
        dll_df: pd.DataFrame, 
        pe_header_df: pd.DataFrame, 
        pe_section_df: pd.DataFrame,
        api_function_df: pd.DataFrame,
    ) -> pd.DataFrame:
    # Preprocess data
    new_dll_df = process_dll_data(dll_df)
    new_pe_header_df = process_pe_header_data(pe_header_df)
    new_pe_section_df = process_pe_section_data(pe_section_df)
    new_api_function_df = process_api_function_data(api_function_df)

    # Merger to input
    master_df = new_dll_df.copy()
    master_df = pd.merge(master_df, new_api_function_df, on='ID', how='left')
    master_df = pd.merge(master_df, new_pe_header_df, on='ID', how='left')
    master_df = pd.merge(master_df, new_pe_section_df, on='ID', how='left')

    # Pad and tokenize
    dll_tokenizer = Tokenizer(num_words=DLL_VOCAB_SIZE, oov_token="<unk>")
    dll_tokenizer.fit_on_texts(master_df['DLL_Sequence'])
    dll_sequences = dll_tokenizer.texts_to_sequences(master_df['DLL_Sequence'])
    dll_padded = pad_sequences(dll_sequences, maxlen=MAX_DLL_SEQ_LENGTH, padding='post', truncating='post')

    api_tokenizer = Tokenizer(num_words=API_VOCAB_SIZE, oov_token="<unk>")
    api_tokenizer.fit_on_texts(master_df['API_Sequence'])
    api_sequences = api_tokenizer.texts_to_sequences(master_df['API_Sequence'])
    api_padded = pad_sequences(api_sequences, maxlen=MAX_API_SEQ_LENGTH, padding='post', truncating='post')

    structured_feature_cols = [col for col in master_df.columns if col.startswith('Header_') or col.startswith('Sections_')]
    X_structured_raw = master_df[structured_feature_cols].values.astype(np.float32)
    scaler = StandardScaler()
    X_structured = scaler.fit_transform(X_structured_raw)

    final_input = [dll_padded, api_padded, X_structured]

    # Make prediction
    prediction = model.predict(final_input)
    predict_class = prediction.argmax(axis=1)

    # Create result df
    result_df = pd.DataFrame(columns=["sha256", "detection", "classifier"])
    result_df['sha256'] = master_df['ID']
    result_df['classifier'] = predict_class
    
    for i in range(len(result_df)):
        classifier = label_decoder(result_df.loc[i, 'classifier'])
        detection = detection_decoder(classifier)
        result_df.loc[i, 'classifier'] = classifier
        result_df.loc[i, 'detection'] = detection

    return result_df