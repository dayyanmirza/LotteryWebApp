from datetime import datetime

import bcrypt
import pyotp
from cryptography.fernet import Fernet
from flask_login import UserMixin
from app import db, app


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # Lotterykey information.
    lotterykey = db.Column(db.BLOB)

    # PIN key
    pinkey = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')

    # Define the relationship to Draw
    draws = db.relationship('Draw')

    def __init__(self, email, firstname, lastname, phone, password, role, lotterykey):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        # Added hashpw function to the password.
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        # Generate (encryption) key
        self.lotterykey = Fernet.generate_key()
        # Generate PIN key
        self.pinkey = pyotp.random_base32()


class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self, user_id, numbers, master_draw, lottery_round, lotterykey):
        self.user_id = user_id
        # Encrypt the numbers.
        self.numbers = encrypt(numbers, lotterykey)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round


# Added encrypt function
def encrypt(data, lotterykey):
    return Fernet(lotterykey).encrypt(bytes(data, 'utf-8'))


# Added decrypt function
def decrypt(data, lotterykey):
    return Fernet(lotterykey).decrypt(data).decode('utf-8')


# added the view lottery function so that
def view_lottery(self, lotterykey):
    self.title = decrypt(self.number, lotterykey)


def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')

        db.session.add(admin)
        db.session.commit()
