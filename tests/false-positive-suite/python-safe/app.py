# python-safe/app.py - Flask SQLAlchemy Safe Endpoints

from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, mapped_column
from sqlalchemy.exc import SQLAlchemyError
import os

app = Flask(__name__)

# Safe connection with SQLAlchemy
db_url = os.getenv('DATABASE_URL', 'postgresql://testuser:rootpass@postgres-safe:5432/testdb')
engine = create_engine(db_url, pool_pre_ping=True)
Session = sessionmaker(bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = mapped_column(Integer, primary_key=True)
    name = mapped_column(String(100))
    email = mapped_column(String(100))

@app.route('/')
def index():
    return jsonify({
        'service': 'Python False Positive Test Suite (SQLAlchemy)',
        'endpoints': [
            '/sqlalchemy-orm - ORM query (safe)',
            '/sqlalchemy-core - Core select (safe)',
            '/sqlalchemy-text - Text with bind params (safe)',
            '/sqlalchemy-bulk - Bulk insert (safe)',
            '/nosql-json - JSON file storage (no SQL)'
        ]
    })

# TEST 11: SQLAlchemy ORM (TRUE SAFE)
@app.route('/sqlalchemy-orm')
def sqlalchemy_orm():
    user_id = request.args.get('id', '1')
    session = Session()
    try:
        # SAFE - ORM handles parameterization
        user = session.get(User, int(user_id))
        return jsonify({
            'safe': True,
            'method': 'SQLAlchemy ORM get()',
            'found': user is not None
        })
    except (SQLAlchemyError, ValueError) as e:
        return jsonify({'safe': True, 'error': str(e)}), 400
    finally:
        session.close()

# TEST 12: SQLAlchemy Core (SAFE)
@app.route('/sqlalchemy-core')
def sqlalchemy_core():
    user_id = request.args.get('id', '1')
    session = Session()
    try:
        # SAFE - Core select with where clause
        from sqlalchemy import select
        stmt = select(User).where(User.id == int(user_id))  # Bound parameter
        result = session.execute(stmt).scalars().first()
        return jsonify({
            'safe': True,
            'method': 'SQLAlchemy Core select',
            'found': result is not None
        })
    except (SQLAlchemyError, ValueError) as e:
        return jsonify({'safe': True, 'error': str(e)}), 400
    finally:
        session.close()

# TEST 13: SQLAlchemy Text with Binds (SAFE)
@app.route('/sqlalchemy-text')
def sqlalchemy_text():
    name = request.args.get('name', 'test')
    session = Session()
    try:
        # SAFE - text() with bind parameters
        stmt = text("SELECT * FROM users WHERE name = :name").bindparams(name=name)
        result = session.execute(stmt).mappings().all()
        return jsonify({
            'safe': True,
            'method': 'SQLAlchemy text() with binds',
            'results': len(result)
        })
    except SQLAlchemyError as e:
        return jsonify({'safe': True, 'error': str(e)}), 400
    finally:
        session.close()

# TEST 14: Bulk Insert with Parameters (SAFE)
@app.route('/sqlalchemy-bulk', methods=['POST'])
def sqlalchemy_bulk():
    users = request.json.get('users', [])
    session = Session()
    try:
        # SAFE - Bulk ORM insert
        user_objects = [User(name=u.get('name'), email=u.get('email')) for u in users]
        session.bulk_save_objects(user_objects)
        session.commit()
        return jsonify({
            'safe': True,
            'method': 'SQLAlchemy bulk insert',
            'inserted': len(user_objects)
        })
    except SQLAlchemyError as e:
        session.rollback()
        return jsonify({'safe': True, 'error': str(e)}), 400
    finally:
        session.close()

# TEST 15: Non-SQL JSON Storage
@app.route('/nosql-json', methods=['GET', 'POST'])
def nosql_json():
    import json
    
    if request.method == 'POST':
        data = request.json
        # Store in JSON file, not SQL
        with open('/tmp/data.json', 'a') as f:
            json.dump(data, f)
            f.write('\n')
        return jsonify({'safe': True, 'method': 'JSON file storage', 'stored': True})
    else:
        # Read from JSON
        try:
            with open('/tmp/data.json', 'r') as f:
                lines = f.readlines()
                data = [json.loads(line) for line in lines[-10:]]  # Last 10 entries
            return jsonify({'safe': True, 'method': 'JSON file read', 'entries': len(data)})
        except FileNotFoundError:
            return jsonify({'safe': True, 'entries': 0})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
