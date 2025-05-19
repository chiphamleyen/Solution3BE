from fastapi import APIRouter, Depends, Query, UploadFile, File

from app.dto.common import BasePaginationResponseData
from app.services.prediction_services import PredictionService
from app.helpers.auth_helpers import get_current_user

router = APIRouter(tags=['Prediction'], prefix="/prediction")

@router.post(
    "/file_upload",
    response_model=BasePaginationResponseData,
)
async def file_upload(
    dll_file: UploadFile = File(...),
    pe_header_file: UploadFile = File(...),
    pe_section_file: UploadFile = File(...),
    api_function_file: UploadFile = File(...),
    current_user: str = Depends(get_current_user),
):
    # validate file size
    dll_file_size = await dll_file.read()
    await dll_file.close()
    pe_header_file_size = await pe_header_file.read()
    await pe_header_file.close()
    pe_section_file_size = await pe_section_file.read()
    await pe_section_file.close()
    api_function_file_size = await api_function_file.read()
    await api_function_file.close()
    
    if len(dll_file_size) > 10_000_000: # 10MB limit
        return BasePaginationResponseData(
            message="DLL file size exceeds 10MB limit",
            error_code=400
        )
    if len(pe_header_file_size) > 10_000_000: # 10MB limit
        return BasePaginationResponseData(
            message="Header file size exceeds 10MB limit",
            error_code=400
        )
    if len(pe_section_file_size) > 10_000_000: # 10MB limit
        return BasePaginationResponseData(
            message="Section file size exceeds 10MB limit",
            error_code=400
        )
    if len(api_function_file_size) > 10_000_000: # 10MB limit
        return BasePaginationResponseData(
            message="API function file size exceeds 10MB limit",
            error_code=400
        )

    user_id, role = current_user
    prediction_data = await PredictionService.get_prediction(
        dll_file=dll_file_size,
        pe_header_file=pe_header_file_size,
        pe_section_file=pe_section_file_size,
        api_function_file=api_function_file_size,
        user_id=user_id,
        role=role
    )
    return BasePaginationResponseData(
        items=prediction_data,
        total=len(prediction_data),
        page=1,
        size=len(prediction_data),
    )