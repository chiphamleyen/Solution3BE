from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query

from app.dto.common import BasePaginationResponseData, BaseResponse
from app.dto.report_dto import HistoryResponse
from app.models.user import UserRoleEnum
from app.services.history_services import HistoryService
from app.helpers.auth_helpers import get_current_user

router = APIRouter(tags=['History'], prefix="/history")

@router.get(
    "/user_history",
    response_model=BasePaginationResponseData,
)
async def user_history(
    min_date: datetime = Query(...),
    max_date: datetime = Query(...),
    page: int = Query(1),
    size: int = Query(10),
    classifier: Optional[str] = Query(None),
    current_user: str = Depends(get_current_user),
):
    user_id, role = current_user
    history_data, total = await HistoryService.get_history_data(
        min_date=min_date, 
        max_date=max_date, 
        page=page, 
        size=size, 
        classifier=classifier,
        user_id=user_id
    )
    return BasePaginationResponseData(
        items=history_data,
        page=page,
        size=size,
        total=total
    )

@router.get(
    "/all_history",
    response_model=BasePaginationResponseData,
)
async def all_history(
    min_date: datetime = Query(...),
    max_date: datetime = Query(...),
    page: int = Query(1),
    size: int = Query(10),
    classifier: Optional[str] = Query(None),
    current_user: str = Depends(get_current_user),
):
    user_id, role = current_user
    if role != UserRoleEnum.ADMIN.value:
        return BasePaginationResponseData(
            error_code=403,
            message="Permission denied"
        )
    history_data, total = await HistoryService.get_history_data(
        min_date=min_date,
        max_date=max_date,
        page=page,
        size=size,
        classifier=classifier,
        user_id=None
    )
    return BasePaginationResponseData(
        items=history_data,
        page=page,
        size=size,
        total=total
    )

@router.get(
    "/{history_id}",
    response_model=HistoryResponse,
)
async def get_by_id(
    history_id: str,
    current_user: str = Depends(get_current_user),
):
    user_id, role = current_user
    history_data = await HistoryService.get_by_id(history_id)
    return HistoryResponse(
        message="Success",
        data=history_data
    )