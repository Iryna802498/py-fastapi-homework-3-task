from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from database import get_db
from schemas.accounts import (
    UserCreate,
    UserActivateToken,
    UserPasswordReset,
    UserResetPasswordComlete,
    UserLoginRequest,
    RefreshTokenRequest,
    AccessTokenResponse
)
from security.interfaces import JWTAuthManagerInterface
from crud.accounts import (
    register_user_with_credentials,
    get_activation_token_by_user_email,
    reset_password_token,
    reset_password_complete,
    login_user_with_credentials,
    new_access_token
)

router = APIRouter()


@router.post("/register/", status_code=201)
async def register_user(
    user_create: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    response = await register_user_with_credentials(
        db=db,
        user_create=user_create
    )
    return response


@router.post("/activate/", status_code=200)
async def activate_account(
    user_request: UserActivateToken,
    db: AsyncSession = Depends(get_db)
):
    response = await get_activation_token_by_user_email(
        db=db,
        user_request=user_request
    )
    return response


@router.post("/password-reset/request/", status_code=200)
async def create_password_reset_token(
    user_request: UserPasswordReset,
    db: AsyncSession = Depends(get_db)
):
    response = await reset_password_token(
        db=db,
        user_request=user_request
    )
    return response


@router.post("/reset-password/complete/", status_code=200)
async def complete_reset_password(
    user_request: UserResetPasswordComlete,
    db: AsyncSession = Depends(get_db)
):
    response = await reset_password_complete(
        db=db,
        user_request=user_request
    )
    return response


@router.post("/login/", status_code=201)
async def login(
    user_request: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    response = await login_user_with_credentials(
        db=db,
        user_request=user_request,
        jwt_manager=jwt_manager,
        settings=settings
    )
    return response


@router.post("/refresh/", response_model=AccessTokenResponse)
async def access_token(
    user_request: RefreshTokenRequest,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db)
):
    response = await new_access_token(
        db=db,
        jwt_manager=jwt_manager,
        user_request=user_request
    )
    return response
