from app import db
import os

try:
    os.remove('./app.db')
except Exception as e:
    print(e)

db.create_all()
