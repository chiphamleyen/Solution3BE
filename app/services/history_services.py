import logging
from datetime import datetime
from typing import List, Optional

from beanie import PydanticObjectId

from app.models.history import History, ClassifierEnum
from app.dto.report_dto import HistoryResponseData
from app.helpers.exceptions import NotFoundException

_logger = logging.getLogger(__name__)

class HistoryService:
    @staticmethod
    async def get_by_id(history_id: str) -> HistoryResponseData:
        query = History.find_one(History.id == PydanticObjectId(history_id))
        return await query.project(HistoryResponseData)

    @staticmethod
    async def get_history_data(
        min_date: datetime, 
        max_date: datetime, 
        page: int, 
        size: int, 
        classifier: Optional[str] = None, 
        user_id: Optional[str] = None
    ) -> tuple[List[HistoryResponseData], int]:
        if user_id is not None:
            query = History.find(
                History.submitter_id == user_id,
                History.created_at >= min_date,
                History.created_at <= max_date
            )
        else:
            query = History.find(
                History.created_at >= min_date,
                History.created_at <= max_date
            )
        if classifier is not None:
            query = query.find(History.classifier == ClassifierEnum[classifier])

        skip = (page - 1) * size
        count = await query.count()
        history_data = await query.skip(skip).limit(size).project(HistoryResponseData).to_list()
        return history_data, count