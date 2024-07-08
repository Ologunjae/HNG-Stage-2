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
# from flask_swagger_ui import get_swaggerui_blueprint


app = Flask(__name__)
load_dotenv()
# app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:greatone@localhost:5432/myorderdb"
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('db_con')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('secret_key')

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = 'users'

    userId = db.Column(db.String, primary_key=True, unique=True)
    firstName = db.Column(db.String, nullable=False)
    lastName = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)
    organisations = db.relationship('Organisation', secondary='user_organisation')

class Organisation(db.Model):
    __tablename__ = 'organisations'

    orgId = db.Column(db.String, primary_key=True, unique=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)

user_organisation = db.Table('user_organisation',
                             db.Column('user_id', db.String, db.ForeignKey('users.userId'), primary_key=True),
                             db.Column('organisation_id', db.String, db.ForeignKey('organisations.orgId'),
                                       primary_key=True))

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
    

    try:
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        user = User(
            userId=data['userId'],
            firstName=data['firstName'],
            lastName=data['lastName'],
            email=data['email'],
            password=hashed_password,
            phone=data.get('phone')
        )
        db.session.add(user)
        db.session.commit()

        # Create default organization
        org_name = f"{data['firstName']}'s Organisation"
        org = Organisation(
            orgId=user.userId,
            name=org_name,
            description=''
        )
        db.session.add(org)
        db.session.commit()

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

    except IntegrityError as e:
        db.session.rollback()
        field = str(e.orig.diag.column_name)
        message = f"{field.capitalize()} already exists."
        return jsonify({'errors': [{'field': field, 'message': message}]}), 422

    except Exception as e:
        db.session.rollback()

        return jsonify({'errors': [{'message': str(e)}]}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'Bad request', 'message': 'Email and password are required.', 'statusCode': 400}), 400

    user = User.query.filter_by(email=email).first()

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
    current_user_id = get_jwt_identity()

    # Check if the user is allowed to access the requested user's data
    if user_id != current_user_id:
        org = Organisation.query.filter(Organisation.orgId == user_id).first()

        if not org:
            return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

        user_belongs_to_org = db.session.query(Organisation, User).filter(User.userId == current_user_id).filter(
            Organisation.orgId == user_id).first()

        if not user_belongs_to_org:
            return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user = User.query.filter_by(userId=user_id).first()

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
    user_orgs = Organisation.query.filter(Organisation.orgId == current_user_id).all()

    organisations = []
    for org in user_orgs:
        organisations.append({
            'orgId': org.orgId,
            'name': org.name,
            'description': org.description
        })

    return jsonify({
        'status': 'success',
        'message': 'Organisations retrieved successfully',
        'data': {
            'organisations': organisations
        }
    }), 200


@app.route('/api/organisations/<org_id>', methods=['GET'])
@jwt_required()
def get_organisation(org_id):
    current_user_id = get_jwt_identity()
    org = Organisation.query.filter(Organisation.orgId == org_id).first()

    if not org:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found', 'statusCode': 400}), 400

    user_belongs_to_org = db.session.query(Organisation, User).filter(User.userId == current_user_id).filter(
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
        orgId= current_user_id,
        name=data['name'],
        description=data.get('description', '')
    )

    db.session.add(org)
    db.session.commit()

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

    org = Organisation.query.filter(Organisation.orgId == org_id).first()

    if not org:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found', 'statusCode': 400}), 400

    user = User.query.filter(User.userId == user_id).first()

    if not user:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user_belongs_to_org = db.session.query(Organisation, User).filter(User.userId == user_id).filter(Organisation.orgId == org_id).first()

    if not user_belongs_to_org:
        return jsonify({'status': 'Bad request', 'message': 'User not found', 'statusCode': 400}), 400

    user.organisations.append(org)
    db.session.commit()

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