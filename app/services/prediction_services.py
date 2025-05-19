import logging
from datetime import datetime
import io
from typing import List

import pandas as pd

from app.models.history import History, ClassifierEnum
from app.helpers.prediction import get_prediction
from app.dto.report_dto import HistoryResponseDataWihtoutId
from app.helpers.exceptions import BadRequestException

_logger = logging.getLogger(__name__)

class PredictionService:
    @staticmethod
    async def save_prediction(
        list_of_prediction: List[History],
    ):
        await History.insert_many(list_of_prediction)
        prediction_data = []
        for prediction in list_of_prediction:
            prediction_data.append(HistoryResponseDataWihtoutId(**prediction.model_dump()))
        return prediction_data
    
    @staticmethod
    async def get_prediction(
        dll_file: bytes, 
        pe_header_file: bytes,
        pe_section_file: bytes,
        api_function_file: bytes,
        user_id: str, 
        role: str
    ):
        dll_df = pd.read_csv(io.BytesIO(dll_file), encoding='utf-8', sep=",")
        pe_header_df = pd.read_csv(io.BytesIO(pe_header_file), encoding='utf-8', sep=",")
        pe_section_df = pd.read_csv(io.BytesIO(pe_section_file), encoding='utf-8', sep=",")
        api_function_df = pd.read_csv(io.BytesIO(api_function_file), encoding='utf-8', sep=",")

        # try:
        prediction_df = get_prediction(
            dll_df=dll_df,
            pe_header_df=pe_header_df,
            pe_section_df=pe_section_df,
            api_function_df=api_function_df,
        )
        # except Exception as e:
        #     _logger.error(f"Error in prediction: {e}")
        #     raise BadRequestException("File format is not correct")

        history_data = []
        for index, row in prediction_df.iterrows():
            history = History(
                submitter_id=user_id,
                submitter_role=role,
                sha_256_hash=row['sha256'],
                detection=bool(row['detection']),
                classifier=ClassifierEnum[row['classifier']],
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
            history_data.append(history)

        prediction_data = await PredictionService.save_prediction(history_data)
        return prediction_data