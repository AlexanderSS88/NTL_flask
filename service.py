import pydantic
import atexit
import re
from sqlalchemy import Column, Integer, String, \
    DateTime, create_engine, func, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from flask import Flask, jsonify
from flask.views import MethodView
from flask import request
from typing import Type, Union, Optional


application = Flask('app')
bcrypt = Bcrypt(application)
"""*********************Вводим пароль******************************"""
DSN = f'postgresql://postgres:***ПАССВОРД***@127.0.0.1:5431/ntl_flask'
engine = create_engine(DSN)
Base = declarative_base()
Session = sessionmaker(bind=engine)
psw_regex = re.compile("^(?=.*[a-z_])")
atexit.register(lambda: engine.dispose())


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    psw = Column(String(100), nullable=False)
    mail = Column(String(100))
    advertising = relationship("AdvertisingModel", backref="user")

    @classmethod
    def register_user(cls,
                      session: Session,
                      name: str,
                      psw: str,
                      mail=''
                      ):
        new_user = UserModel(
            name=name,
            mail=mail,
            psw=bcrypt.generate_password_hash(psw.encode()).decode()
            )
        session.add(new_user)
        try:
            session.commit()
            return new_user
        except IntegrityError:
            raise HttpError(409, 'User with that name already exists')

    def check_password(self, psw: str):
        return bcrypt.check_password_hash(self.psw.encode(), psw.encode())

    def to_dict(self):
        return {
            "name": self.name,
            "mail": self.mail,
            "id": self.id,
            "psw": self.psw
            }
    Base.metadata.create_all(engine)


class AdvertisingModel(Base):
    __tablename__ = "advertisings"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(100), nullable=False, unique=True)
    description = Column(String(300))
    create_date = Column(DateTime, server_default=func.now())
    Base.metadata.create_all(engine)


class ValidateCreateUserSchema(pydantic.BaseModel):
    name: str
    psw: str
    mail: Optional[str]

    @pydantic.validator('mail', "psw", 'name')
    def check_long(cls, value: str):
        if len(value) > 100:
            raise ValueError('Text must be less than 100 characters')
        return value

    @pydantic.validator("psw")
    def strong_password(cls, value: str):
        if not re.search(psw_regex, value):
            raise ValueError("password to easy")
        return value


class ValidateCreateAdvSchema(pydantic.BaseModel):
    title: str
    description: Optional[str]

    @pydantic.validator('title')
    def check_title(cls, value: str):
        if len(value) > 100:
            raise ValueError('Title length is too long')
        return value

    @pydantic.validator('description')
    def check_description(cls, value: str):
        if len(value) > 300:
            raise ValueError('Description length is too long')
        return value


class ValidatePatchAdvSchema(pydantic.BaseModel):
    title: Optional[str]
    description: Optional[str]
    @pydantic.validator("title")
    def check_title(cls, value: str):
        if len(value) > 100:
            raise ValueError("Title length is too long")
        return value
    @pydantic.validator("description")
    def check_description(cls, value: str):
        if len(value) > 300:
            raise ValueError("Description length is too long")
        return value


def validate(data: dict,
             validation_class: Type[ValidateCreateUserSchema] |
                               Type[ValidateCreateAdvSchema] |
                               Type[ValidatePatchAdvSchema]):
    try:
        return validation_class(**data).dict(exclude_none=True)
    except pydantic.ValidationError as err:
        raise HttpError(400, err.errors())



class UserView(MethodView):

    def post(self):
        with Session() as session:
            new_user = request.json
            reg_data = validate(new_user, ValidateCreateUserSchema)
            UserModel.register_user(session, **reg_data).to_dict()
            user_id_create = get_user_id_and_check_psw(new_user, session)
            from_db = get_item_orm(user_id_create, UserModel, session)
            return jsonify(from_db.to_dict())

    def get(self, user_id: int):
        login_data = request.json
        with Session() as session:
            user_data = get_item_orm(user_id, UserModel, session)
            if user_data is None or not \
                    user_data.check_password(login_data["psw"]):
                raise HttpError(401, "incorrect user or password")
            return jsonify(user_data.to_dict())



class AdvertisingView(MethodView):

    def get(self, advrts_id: int):
        with Session() as session:
            advrts = get_item_orm(advrts_id, AdvertisingModel, session)
            if advrts is None:
                raise HttpError(404, 'User not authorized')
            return jsonify({
                "Status": "OK",
                "id":  advrts.id,
                "owner_name":  advrts.user.name,
                "title":  advrts.title,
                "description":  advrts.description,
                "create_date":  advrts.create_date
            })

    def post(self):
        with Session() as session:
            try:
                advrts = AdvertisingModel(
                    **validate(
                        request.args,
                        ValidateCreateAdvSchema
                        )
                    )
                user_id = get_user_id_and_check_psw(
                    request.json,
                    session)
                setattr(advrts, 'owner_id', user_id)
                session.add(advrts)
                session.commit()
            except IntegrityError:
                raise HttpError(
                    409,
                    'Advertising with that title already exists'
                    )
            Base.metadata.create_all(engine)
            return jsonify({"Status": "OK",
                            'Advertising id': advrts.id})

    def patch(self, advrts_id: int):
        with Session() as session:
            validate_patch_data = validate(
                request.args,
                ValidatePatchAdvSchema)
            user_id = get_user_id_and_check_psw(request.json, session)
            advrts_user_id = (session.query(AdvertisingModel).
                              filter(AdvertisingModel.id == advrts_id).
                              first()).owner_id
            if user_id != advrts_user_id:
                raise HttpError(
                    403,
                    "Denied! You are not owner of this advertising"
                    )
            advrts = get_item_orm(advrts_id, AdvertisingModel, session)
            for key, value in validate_patch_data.items():
                setattr(advrts, key, value)
            session.commit()
        return jsonify({"Status": "OK",
                        'Advertising to PATCH id': advrts_id})

    def delete(self, advrts_id: int):
        with Session() as session:
            user_id = get_user_id_and_check_psw(request.json, session)
            advrts_user_id = (session.query(AdvertisingModel).
                              filter(AdvertisingModel.id == advrts_id).
                              first()).owner_id
            if user_id != advrts_user_id:
                raise HttpError(
                    403,
                    "Denied! You are not owner of this advertising"
                    )
            advrts = get_item_orm(advrts_id, AdvertisingModel, session)
            session.delete(advrts)
            session.commit()
            return jsonify({"Status": "OK",
                            "Advertising to delete id": advrts.id,
                            "Owner of advertising id": advrts_user_id,
                            "User's id want to delete adv": user_id})



class HttpError(Exception):
    def __init__(self, status_code: int, message: Union[str, list, dict]):
        self.status_code = status_code
        self.message = message

@application.errorhandler(HttpError)
def error_handler(error: HttpError):
    response = jsonify({"message": error.message})
    response.status_code = error.status_code
    return response


def get_item_orm(
        item_id: int,
        model_base: Type[AdvertisingModel] | Type[UserModel],
        session: Session):
    orm_item = session.query(model_base).get(item_id)
    if orm_item is None:
        raise HttpError(404, 'Position not found')
    return orm_item


def get_user_id_and_check_psw(item_json: dict, session: Session):
    user = (session.query(UserModel).
            filter(UserModel.name == item_json["name"]).
            first())
    if user is None or not user.check_password(item_json["psw"]):
        raise HttpError(401, "incorrect user or password")
    return user.id


application.add_url_rule(
    "/flask/user",
    view_func=UserView.as_view("crt_user"),
    methods=['POST']
    )

application.add_url_rule(
    "/flask/user/<int:user_id>",
    view_func=UserView.as_view("get_user"),
    methods=["GET"]
    )

application.add_url_rule(
    '/flask/user/adv',
    view_func=AdvertisingView.as_view('crt_advrts'),
    methods=['POST']
    )

application.add_url_rule(
    '/flask/user/adv/<int:advrts_id>',
    view_func=AdvertisingView.as_view('advrts_view'),
    methods=['GET', 'DELETE', 'PATCH']
    )

application.run()
