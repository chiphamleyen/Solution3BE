from datetime import datetime
from typing import List
from beanie import PydanticObjectId
from pydantic import BaseModel, Field
from app.dto.common import BaseResponseData

class HistoryResponseDataWihtoutId(BaseModel):
    sha_256_hash: str
    detection: bool
    classifier: str
    created_at: datetime

class HistoryResponseData(HistoryResponseDataWihtoutId):
    id: PydanticObjectId = Field(alias='_id')
    sha_256_hash: str
    detection: bool
    classifier: str
    created_at: datetime

class HistoryResponse(BaseResponseData):
    data: HistoryResponseData

class ClassifierResponseData(BaseModel):
    type: str
    total: int

class ReportResponseData(BaseModel):
    total: int = 0
    detection_benign: int = 0
    detection_malware: int = 0
    classifier: List[ClassifierResponseData] = []

class ReportResponse(BaseResponseData):
    data: ReportResponseData