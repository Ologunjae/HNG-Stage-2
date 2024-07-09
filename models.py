from sqlalchemy import create_engine, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Table
from dotenv import load_dotenv
import os
load_dotenv()
Base = declarative_base()

user_organisation = Table(
    'user_organisation', Base.metadata,
    Column('user_id', String, ForeignKey('users.userId'), primary_key=True),
    Column('organisation_id', String, ForeignKey('organisations.orgId'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'

    userId = Column(String, primary_key=True, unique=True)
    firstName = Column(String, nullable=False)
    lastName = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    phone = Column(String)

    organisations = relationship('Organisation', secondary=user_organisation, back_populates='users')

class Organisation(Base):
    __tablename__ = 'organisations'

    orgId = Column(String, primary_key=True, unique=True)
    name = Column(String, nullable=False)
    description = Column(String)

    users = relationship('User', secondary=user_organisation, back_populates='organisations')

# Create the engine and tables
engine = create_engine(os.getenv('db_con'))
Base.metadata.create_all(engine)

# Create a session
Session = sessionmaker(bind=engine)
Session().rollback()
session = Session()