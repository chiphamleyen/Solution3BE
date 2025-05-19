from pymongo import ASCENDING, IndexModel

from app.models.base import RootModel, RootEnum
from app.models.user import UserRoleEnum

class ClassifierEnum(RootEnum):
    RedLineStealer = "RedLineStealer"
    Downloader = "Downloader"
    RAT = "RAT"
    BankingTrojan = "BankingTrojan"
    SnakeKeyLogger = "SnakeKeyLogger"
    Spyware = "Spyware"
    Benign = "Benign"

class History(RootModel):
    class Settings:
        name = "history"
        indexes = [
            IndexModel(
                [
                    ("submitter_id", ASCENDING),
                ]
            )
        ]
    submitter_id: str #ID of the submitter
    submitter_role: UserRoleEnum
    sha_256_hash: str
    detection: bool
    classifier: ClassifierEnum