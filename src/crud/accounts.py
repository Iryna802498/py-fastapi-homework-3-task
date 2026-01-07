from datetime import datetime, timezone, timedelta
from typing import cast, Dict
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, and_
from sqlalchemy.exc import SQLAlchemyError
from security.passwords import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface
from config.settings import BaseAppSettings
from database.models.accounts import (
    UserModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserCreate,
    UserRead,
    UserActivateToken,
    UserPasswordReset,
    UserResetPasswordComlete,
    UserLoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    AccessTokenResponse
)
from security.utils import generate_secure_token


def is_token_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


def generate_token_with_expiry(days: int = 1) -> tuple[str, datetime]:
    return (
        generate_secure_token(),
        datetime.now(timezone.utc) + timedelta(days=days)
    )


async def add_activation_token(
    db: AsyncSession,
    user_id: int
):
    token, expires_at = generate_token_with_expiry()
    await db.execute(
        delete(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == user_id)
    )
    token_model = ActivationTokenModel(
        user_id=cast(int, user_id),
        token=token,
        expires_at=expires_at
    )
    db.add(token_model)
    await db.flush()


async def add_password_reset_token(
    db: AsyncSession,
    user_id: int
):
    await db.execute(
        delete(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user_id)
    )
    token, expires_at = generate_token_with_expiry()
    token_model = PasswordResetTokenModel(
        user_id=cast(int, user_id),
        token=token,
        expires_at=expires_at
    )
    db.add(token_model)
    await db.flush()


async def get_user_by_id(db: AsyncSession, user_id: int):
    user = await db.execute(
        select(UserModel)
        .where(UserModel.id == user_id)
    )
    result = user.scalar_one_or_none()
    return result


async def get_user_by_email(
    db: AsyncSession,
    user_email: str
):
    db_user = await db.execute(
        select(UserModel).where(
            UserModel.email == user_email
        )
    )
    result = db_user.scalar_one_or_none()
    return result


async def register_user_with_credentials(
    db: AsyncSession,
    user_create: UserCreate
) -> UserRead:
    try:
        async with db.begin():
            user = await db.execute(
                select(UserModel)
                .where(UserModel.email == user_create.email)
            )
            existing = user.scalars().first()
            if existing:
                raise HTTPException(
                    status_code=409,
                    detail=(f"A user with this email "
                            f"{user_create.email} already exists.")
                )
            hashed = hash_password(user_create.password)
            db_user = UserModel(
                email=user_create.email,
                hashed_password=hashed,
                group_id=UserGroupEnum.USER.value
            )
            db.add(db_user)
            await db.flush()
            if db_user:
                await add_activation_token(
                    db=db,
                    user_id=db_user.id
                )
        return UserRead.model_validate(
            db_user
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


async def get_activation_token_by_user_email(
        db: AsyncSession,
        user_request: UserActivateToken
) -> Dict[str, str]:
    db_user = await get_user_by_email(
        db=db,
        user_email=user_request.email
    )
    query = select(ActivationTokenModel).where(
        ActivationTokenModel.user == db_user
    )
    result = await db.execute(query)
    token_record = result.scalars().first()
    if token_record is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if token_record.token != user_request.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if is_token_expired(token_record.expires_at):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    db_user.is_active = True
    await db.execute(
        delete(ActivationTokenModel)
        .where(ActivationTokenModel.user == db_user)
    )
    await db.flush()
    return {
        "message": "User account activated successfully."
    }


async def reset_password_token(
    db: AsyncSession,
    user_request: UserPasswordReset
) -> Dict[str, str]:
    query = select(UserModel).where(
        and_(
            UserModel.email == user_request.email,
            UserModel.is_active.is_(True)
        )
    )
    db_user = await db.execute(query)
    result = db_user.scalars().first()
    if result:
        await add_password_reset_token(
            db=db,
            user_id=result.id
        )
    return {
        "message": "If you are registered, "
        "you will receive an email with instructions."
    }


async def reset_password_complete(
    db: AsyncSession,
    user_request: UserResetPasswordComlete
) -> Dict[str, str]:
    try:
        async with db.begin():
            db_user = await get_user_by_email(
                db=db,
                user_email=user_request.email
            )
            if not db_user or db_user.is_active is False:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid email or token."
                )
            query = select(PasswordResetTokenModel).where(
                and_(
                        PasswordResetTokenModel.user == db_user,
                        PasswordResetTokenModel.token == user_request.token
                    )
            )
            result = await db.execute(query)
            token = result.scalars().first()
            if not token:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid email or token."
                )
            if is_token_expired(token.expires_at):
                await db.delete(token)
                raise HTTPException(
                    status_code=400,
                    detail="Invalid email or token."
                )
            hashed = hash_password(user_request.password)
            db_user._hashed_password = hashed
            await db.delete(token)
        return {
            "message": "Password reset successfully."
        }
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


async def login_user_with_credentials(
    db: AsyncSession,
    jwt_manager: JWTAuthManagerInterface,
    user_request: UserLoginRequest,
    settings: BaseAppSettings
) -> TokenResponse:
    try:
        db_user = await get_user_by_email(
            db=db,
            user_email=user_request.email
        )
        if not db_user or not verify_password(
            plain_password=user_request.password,
            hashed_password=db_user._hashed_password
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )
        if db_user.is_active is False:
            raise HTTPException(
                status_code=403,
                detail="User account is not activated."
            )
        create_access_token = jwt_manager.create_access_token(
            data={"sub": str(db_user.id)}
        )
        create_refresh_token = jwt_manager.create_refresh_token(
            data={"sub": str(db_user.id)}
        )
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=create_refresh_token
        )
        async with db.begin():
            db.add(refresh_token)
        return TokenResponse(
            access_token=create_access_token,
            refresh_token=create_refresh_token,
            token_type="bearer"
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


async def new_access_token(
        db: AsyncSession,
        user_request: RefreshTokenRequest,
        jwt_manager: JWTAuthManagerInterface
) -> AccessTokenResponse:
    try:
        token_valid = jwt_manager.decode_refresh_token(
            token=user_request.refresh_token
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    db_refresh_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == user_request.refresh_token
    )
    query = await db.execute(db_refresh_token)
    result = query.scalars().first()
    if not result:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )
    token_user_id = int(token_valid.get("sub"))
    if token_user_id != result.user_id:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )
    db_user = await db.execute(
        select(UserModel)
        .where(UserModel.id == result.user_id)
    )
    user = db_user.scalars().first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )
    access_token = jwt_manager.create_access_token(
        data={"sub": str(user.id)}
    )
    return AccessTokenResponse(
        access_token=access_token
    )
