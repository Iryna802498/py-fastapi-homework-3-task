from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators.accounts import (
    validate_password_strength,
    validate_email
)


class EmailPasswordValidationBase(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def email_valid(cls, value: str) -> str:
        result = validate_email(user_email=value)
        return result

    @field_validator("password")
    @classmethod
    def password_valid(cls, value: str) -> str:
        result = validate_password_strength(password=value)
        return result


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(EmailPasswordValidationBase):
    pass


class UserRead(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivateToken(UserBase):
    token: str


class UserPasswordReset(UserBase):
    pass


class UserResetPasswordComlete(EmailPasswordValidationBase):
    token: str


class UserLoginRequest(EmailPasswordValidationBase):
    pass


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

    model_config = ConfigDict(from_attributes=True)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str

    model_config = ConfigDict(from_attributes=True)
