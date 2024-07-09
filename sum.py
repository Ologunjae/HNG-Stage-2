from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity
)
from dotenv import load_dotenv
import os
import uuid



from models import session, User, Organisation, user_organisation
# from flask_swagger_ui import get_swaggerui_blueprint

# db = session

session.rollback()
app = Flask(__name__)
load_dotenv()
# app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:greatone@localhost:5432/myorderdb"
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('db_con')
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('secret_key')

# db = SQLAlchemy(app)
jwt = JWTManager(app)

# user_organisation = Table('user_organisation',
#                              Column('user_id', String, ForeignKey('users.userId')),
#                              Column('organisation_id', String, ForeignKey('organisations.orgId')))


# class User(Model):
#     __tablename__ = 'users'

#     userId = Column(String, primary_key=True, unique=True)
#     firstName = Column(String, nullable=False)
#     lastName = Column(String, nullable=False)
#     email = Column(String, nullable=False, unique=True)
#     password = Column(String, nullable=False)
#     phone = Column(String)

#     orgs = relationship('Organisation', secondary= user_organisation, back_populates= 'users')

# class Organisation(Model):
#     __tablename__ = 'organisations'

#     orgId = Column(String, primary_key=True, unique=True)
#     name = Column(String, nullable=False)
#     description = Column(String)

#     org_users = relationship('User', secondary= user_organisation, back_populates= 'organisations')


@app.route('/', methods=['GET'])
def status():
    return 'API SUCCESSFUL'

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['firstName', 'lastName', 'email', 'password']
    errors = []
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append({
                'field': field,
                'message': f'{field.capitalize()} is required.'
            })

    if errors:
        print(errors)
        return jsonify({'errors': errors}), 422
    

    # try:
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    org_name = f"{data['firstName']}'s Organisation"
    user = User(
        userId=str(uuid.uuid4()),
        firstName=data['firstName'],
        lastName=data['lastName'],
        email=data['email'],
        password=hashed_password,
        phone=data.get('phone'),
        organisations = [Organisation(
            orgId=str(uuid.uuid4()),
            name=org_name,
            description=''
        )]
    )
    
    # session.add(user)
    # session.commit()

    # Create default organization
    
    

    # user.organisations.append(org.orgId)
    # org.users.append(user.userId)
    session.add(user)
    # session.add(org)
    
    session.commit()

    access_token = create_access_token(identity=user.userId)
    return jsonify({
        'status': 'success',
        'message': 'Registration successful',
        'data': {
            'accessToken': access_token,
            'user': {
                'userId': user.userId,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'email': user.email,
                'phone': user.phone
            }
        }
    }), 201


# except IntegrityError as e:
# session.rollback()
# field = str(e.orig.diag.column_name)
# message = f"{field.capitalize()} already exists."
# return jsonify({'errors': [{'field': field, 'message': message}]}), 422

# except Exception as e:
# session.rollback()

# return jsonify({'errors': [{'message': str(e)}]}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'Bad request', 'message': 'Email and password are required.', 'statusCode': 400}), 400

    user= session.query(User).filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'status': 'Bad request', 'message': 'Authentication failed', 'statusCode': 401}), 401

    access_token = create_access_token(identity=user.userId)
    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'accessToken': access_token,
            'user': {
                'userId': user.userId,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'email': user.email,
                'phone': user.phone
            }
        }
    }), 200


@app.route('/api/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    if len(user_id)<30:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400
    current_user_id = get_jwt_identity()

    # Check if the user is allowed to access the requested user's data
    if user_id != current_user_id:
        org = session.query(Organisation).filter(Organisation.orgId == user_id).first()

        if not org:
            return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

        user_belongs_to_org = session.query(Organisation, User).filter(User.userId == current_user_id).filter(
            Organisation.orgId == user_id).first()

        if not user_belongs_to_org:
            return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user = session.query(User).filter_by(userId=user_id).first()

    if not user:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    return jsonify({
        'status': 'success',
        'message': 'User data retrieved successfully',
        'data': {
            'userId': user.userId,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'email': user.email,
            'phone': user.phone
        }
    }), 200


@app.route('/api/organisations', methods=['GET'])
@jwt_required()
def get_organisations():
    current_user_id = get_jwt_identity()
    user_orgs = session.query(User).filter(User.userId == current_user_id).first()
    # print(user_orgs[0].organisations)
    us_organisations = []
    for org in user_orgs.organisations:
        us_organisations.append({
            'orgId': org.orgId,
            'name': org.name,
            'description': org.description
        })

    return jsonify({
        'status': 'success',
        'message': 'Organisations retrieved successfully',
        'data': {
            'organisations': us_organisations
        }
    }), 200


@app.route('/api/organisations/<org_id>', methods=['GET'])
@jwt_required()
def get_organisation(org_id):
    if len(org_id)<30:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400
    current_user_id = get_jwt_identity()
    current_user_id = get_jwt_identity()
    org = session.query(Organisation).filter(Organisation.orgId == org_id).first()

    if not org:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found', 'statusCode': 400}), 400

    user_belongs_to_org = session.query(Organisation, User).filter(User.userId == current_user_id).filter(
        Organisation.orgId == org_id).first()

    if not user_belongs_to_org:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found', 'statusCode': 400}), 400

    return jsonify({
        'status': 'success',
        'message': 'Organisation data retrieved successfully',
        'data': {
            'orgId': org.orgId,
            'name': org.name,
            'description': org.description
        }
    }), 200


@app.route('/api/organisations', methods=['POST'])
@jwt_required()
def create_organisation():
    data = request.json
    required_fields = ['name']
    errors = []
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append({
                'field': field,
                'message': f'{field.capitalize()} is required.'
            })

    if errors:
        return jsonify({'errors': errors}), 422

    current_user_id = get_jwt_identity()

    org = Organisation(
        orgId= str(uuid.uuid4()),
        name=data['name'],
        description=data.get('description', '')
    )
    try:
        session.add(org)
        session.commit()

    except IntegrityError as e:
        session.rollback()
        field = str(e.orig.diag.column_name)
        message = f"{field.capitalize()} already exists."
        return jsonify({'errors': [{'field': field, 'message': message}]}), 422

    return jsonify({
        'status': 'success',
        'message': 'Organisation created successfully',
        'data': {
            'orgId': org.orgId,
            'name': org.name,
            'description': org.description
        }
    }), 201


@app.route('/api/organisations/<org_id>/users', methods=['POST'])
def add_user_to_organisation(org_id):
    data = request.json
    user_id = data.get('userId')

    if not user_id:
        return jsonify({'status': 'Bad request', 'message': 'User ID is required.', 'statusCode': 400}), 400

    org = session.query(Organisation).filter(Organisation.orgId == org_id).first()

    if not org:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found', 'statusCode': 400}), 400

    user = session.query(User).filter(User.userId == user_id).first()

    if not user:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user_belongs_to_org = session.query(Organisation, User).filter(User.userId == user_id).filter(Organisation.orgId == org_id).first()

    if not user_belongs_to_org:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user.organisations.append(org)
    session.commit()

    return jsonify({
        'status': 'success',
        'message': 'User added to organisation successfully',
        'data': {
            'orgId': org.orgId,
            'name': org.name,
            'description': org.description
        }
    }), 200


if __name__ == '__main__':
    app.run()