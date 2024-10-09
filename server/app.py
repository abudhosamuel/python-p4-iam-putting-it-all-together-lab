#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api, bcrypt
from models import User, Recipe

# Sign-up Feature
class Signup(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            image_url = data.get('image_url', "")
            bio = data.get('bio', "")

            if not username or not password:
                return jsonify({"error": "Username and password are required"}), 422

            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

            new_user = User(
                username=username,
                password_hash=password_hash,
                image_url=image_url,
                bio=bio
            )

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            return jsonify({
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio
            }), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Username already exists"}), 422

        except KeyError as e:
            return jsonify({"error": f"Missing required field: {e}"}), 400

        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Check Session (Auto-login) Feature
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return jsonify({
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }), 200
        return jsonify({"error": "Unauthorized"}), 401

# Login Feature
class Login(Resource):
    def post(self):
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return jsonify({"error": "Username and password are required"}), 401

            user = User.query.filter_by(username=username).first()

            if user and bcrypt.check_password_hash(user._password_hash, password):
                session['user_id'] = user.id
                return jsonify({
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }), 200

            return jsonify({"error": "Invalid username or password"}), 401

        except KeyError as e:
            return jsonify({"error": f"Missing required field: {e}"}), 400

        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Logout Feature
class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None)
            return '', 204
        
        return jsonify({"error": "Unauthorized"}), 401

# Recipe List and Recipe Creation Feature
class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        
        recipes = Recipe.query.all()
        recipes_list = [{
            "title": recipe.title,
            "instructions": recipe.instructions,
            "minutes_to_complete": recipe.minutes_to_complete,
            "user": {
                "id": recipe.user.id,
                "username": recipe.user.username,
                "image_url": recipe.user.image_url,
                "bio": recipe.user.bio
            }
        } for recipe in recipes]

        return jsonify(recipes_list), 200

    def post(self):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or len(instructions) < 50:
            return jsonify({"error": "Title and instructions are required, and instructions must be at least 50 characters long."}), 422

        # Create the new recipe associated with the logged-in user
        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=session['user_id']
        )

        try:
            db.session.add(recipe)
            db.session.commit()

            return jsonify({
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio": recipe.user.bio
                }
            }), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Could not create recipe"}), 422

# API Resource Routes
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
