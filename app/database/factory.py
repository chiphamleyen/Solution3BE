import json
from pathlib import Path
from typing import Type, Union
from beanie import init_beanie, Document
from motor import motor_asyncio

from config.config import get_settings
from app.models.user import User
from app.models.history import History
import logging

_logger = logging.getLogger(__name__)


async def init_collection(col: Type[Document], file_path: Union[str, Path]):
    existing_items = await col.find_all(limit=5).to_list()
    if not existing_items:
        f = open(file_path, encoding="utf-8")
        default_items = json.load(f)
        f.close()
        for default_item in default_items:
            item_id = default_item.get("_id")
            if item_id and item_id.get("$oid"):
                default_item.update({"_id": item_id.get("$oid")})
            item_created_at = default_item.get("created_at")
            if item_created_at and item_created_at.get("$date") and item_created_at.get("$date").get("$numberLong"):
                default_item.update({"created_at": item_created_at.get("$date").get("$numberLong")})
            item_updated_at = default_item.get("updated_at")
            if item_updated_at and item_updated_at.get("$date") and item_updated_at.get("$date").get("$numberLong"):
                default_item.update({"updated_at": item_updated_at.get("$date").get("$numberLong")})
            item = col(**default_item)
            await item.create()
        _logger.info(f"Successfully init data for collection {col.__name__}")


async def initialize():
    # CREATE MOTOR CLIENT
    client = motor_asyncio.AsyncIOMotorClient(get_settings().mongo_dsn, maxPoolSize=5)

    # INIT BEANIE
    await init_beanie(
        client.get_database(),
        document_models=[
            User,
            History,
        ],
    )

    # CREATE DATA
    # await init_collections()

    _logger.info("Database is successfully initialized.")