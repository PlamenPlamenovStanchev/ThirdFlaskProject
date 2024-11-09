from idlelib.iomenu import errors

import jwt

from datetime import datetime, timedelta
from enum import Enum


from flask import Flask, request
from decouple import config
from flask_httpauth import HTTPTokenAuth
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, abort
from flask_migrate import Migrate
from marshmallow import Schema, fields, ValidationError,validate
from password_strength import PasswordPolicy
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql.functions import current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)



app.config['SQLALCHEMY_DATABASE_URI'] = (f"postgresql://"
                                         f"{config('DB_USER')}:"
                                         f"{config('DB_PASS')}@"
                                         f"{config('DB_HOST')}:"
                                         f"{config('DB_PORT')}/"
                                         f"{config('DB_NAME')}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
auth = HTTPTokenAuth(scheme='Bearer')

@auth.verify_token
def verify_token(token):
    try:
       user = User.decode_token(token)
       return user
    except jwt.exceptions.InvalidTokenError as ex:
        abort(401)


def permission_required(required_role): #single role
    def decorator(function):
        def decorated_function(*args, **kwargs):
            current_user = auth.current_user()
            if current_user.role != required_role:
                abort(403)
            return function(*args, **kwargs)
        return decorated_function
    return decorator

class UserRolesEnum(Enum):
    super_admin = "super admin"
    admin = "admin"
    user = "user"

def permissions_required(required_roles: list[UserRolesEnum]): # multiple roles
    def decorator(function):
        def decorated_function(*args, **kwargs):
            # if not isinstance(required_roles, list):
            #     required_roles = [required_roles]
            current_user = auth.current_user()
            if current_user.role in required_roles:
                abort(403)
            return function(*args, **kwargs)
        return decorated_function
    return decorator


def validate_schema(schema):
    def decorator(function):
        def decorated_function(*args, **kwargs):
            schema_object = schema
            data = request.get_json()
            errors = schema_object.validate(data)
            if errors:
                abort(400, errors=errors)
            return function(*args, **kwargs)
        return decorated_function
    return decorator


class User(db.Model):
    __tablename__ = 'user'

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(db.String(120), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(db.String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    create_on: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_on: Mapped[datetime] = mapped_column(onupdate=func.now(), server_default=func.now())
    role: Mapped[UserRolesEnum] = mapped_column(
        db.Enum(UserRolesEnum),
        default=UserRolesEnum.user,
        nullable=False
    )


    def encode_token(self):
        key = config("SECRET_KEY")
        data = {
            'exp': datetime.utcnow() + timedelta(days=2),
            'sub': self.id
        }
        return jwt.encode(data, key,algorithm='HS256')

    @staticmethod
    def decode_token(token):
        key = config("SECRET_KEY")
        data = jwt.decode(token, key, algorithms=['HS256'])
        user_id = data['sub']
        user = db.session.execute(db.select(User).filter_by(id = user_id)).scalar()
        if not user:
            raise jwt.exceptions.InvalidTokenError()
        return user


class ColorEnum(Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class SizeEnum(Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


class Clothes(db.Model):
    __tablename__ = 'clothes'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    color: Mapped[ColorEnum] = mapped_column(
        db.Enum(ColorEnum),
        default=ColorEnum.white,
        nullable=False
    )
    size: Mapped[SizeEnum] = mapped_column(
        db.Enum(SizeEnum),
        default=SizeEnum.s,
        nullable=False
    )
    photo: Mapped[str] = mapped_column(db.String(255), nullable=False)
    create_on: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_on: Mapped[datetime] = mapped_column(onupdate=func.now(), server_default=func.now())


policy = PasswordPolicy.from_names(
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
    nonletters=1,  # need min. 1 non-letter characters (digits, specials, anything)
)
def validate_password_strength(value):
    errors = policy.test(value)
    if errors:
        raise ValidationError(f'Password must contain at least one uppercase letter, at least one number, at least one '
                              f'special character and at least one non letter character')

def validate_full_name(value):
    try:
        first_name, last_name = value.split()
    except ValueError:
        raise ValidationError(f"First and Last name are required fields")
    if len(first_name) < 2 or len(last_name) < 2:
        raise ValidationError(f"first and last name must be at least 2 characters long")


class BaseUserSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.String(required=True, validate=validate.And(validate.Length(max=255), validate_full_name)) # validation using function
    password = fields.String(required=True, validate=validate.And(validate.Length(min=8, max=20),
                             validate_password_strength)) # Validation using function

    # @validates("full_name")
    # def validate_name(self, value):
    #     try:
    #         first_name, last_name = value.split()
    #     except ValueError:
    #         raise ValidationError(
    #             "Full name should consist of first and last name at least"
    #         )
    #
    #     if len(first_name) < 3 or len(last_name) < 3:
    #         raise ValueError("Name should be at least 3 characters")
# Validation using methods

class UserResponseSchema(BaseUserSchema):
    id = fields.Integer

class UsersResource(Resource):
    @validate_schema(BaseUserSchema)
    def post(self):
        data = request.get_json()
        data["password"] = generate_password_hash(data["password"], method="pbkdf2:sha256")
        user = User(**data)
        db.session.add(user)
        try:
            db.session.commit()
            token = user.encode_token()
            return {"token": token}, 201
        except IntegrityError as ex:
            return {"message": "Email already exist, please sign in instead"}, 400
        return errors, 400


class UserLoginResource(Resource):
    def post(self):
        data = request.get_json()
        user = db.session.execute(db.select(User).filter_by(email=data['email'])).scalar()
        if not user:
            raise Exception("Invalid email or password")

        result = check_password_hash(user.password, data["password"])
        if result:
            return {"token": user.encode_token()}
        raise Exception("Invalid email or password")


    # def post(self):
    #     data = request.get_json()
    #     schema = BaseUserSchema()
    #     erorrs = schema.validate(data)
    #     if not erorrs:
    #         data["password"] = generate_password_hash(data["password"], method="pbkdf2:sha256")
    #         user = User(**data)
    #         db.session.add(user)
    #         db.session.commit()
    #         return 201
    #     return 400



class UserResource(Resource):

    @auth.login_required
    @permission_required(UserRolesEnum.admin)
    # @permissions_required([UserRolesEnum.admin, UserRolesEnum.super_admin])
    def get(self, pk):
        user = db.session.execute(db.select(User).filter_by(id=pk)).scalar()
        if not user:
            return {"message": 'user not found'}
        return UserResponseSchema.dump(user)

# class ClothesRouter(Resource):
#     @auth.login_required
#     def get(self):
#         current_user = auth.current_user()
#         clothes = Clothes.query.all()
#   Version 3
  # clothes = db.session.execute(db.select(Clothes)).scalars()
  # resp = ClothesResponseSchema().dump(clothes, many=True)
  # return {"data": resp}, 200

    # @staticmethod
    # def decode_token(token):
    #     try:
    #         result = jwt.decode(jwt=token, key=SECRET_KEY, algorithms=["HS256"])
    #         user = db.session.execute(db.select(User).filter_by(id=result['sub'])).scalar()
    #         if not user:
    #             raise jwt.exceptions.InvalidTokenError()
    #         return user
    #     except jwt.exceptions.InvalidTokenError as ex:
    #         raise Exception("Please login again")


# api.add_resource(ClothesRouter, "/items")
api.add_resource(UsersResource, "/register")
api.add_resource(UserLoginResource, "/login")
api.add_resource(UserResource, "/users/<int:pk>")


