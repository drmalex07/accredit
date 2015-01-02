from sqlalchemy import (Table, Column, Integer, String, DateTime, MetaData, ForeignKey, UniqueConstraint, Index)
from sqlalchemy.orm import (relation, relationship, backref)

from datetime import datetime;

from hashlib import md5

from accredit.model.meta import Base

class User(Base):
    __table__ = Table ('user', Base.metadata,
        Column('uid', Integer(), primary_key=True),
        Column('username', String(64), nullable=True),
        Column('password', String(32), nullable=False),
        Column('description', String(256), nullable=True),
        Column('created_at', DateTime(), nullable=False),
        UniqueConstraint('username'),
    )

    @classmethod
    def digest_password(cls, x):
        return md5(x).hexdigest();

    def __init__(self, username=None, plaintext_password=None, created_at=None, description=None):
        self.username  = username;
        self.password  = User.digest_password(plaintext_password);
        self.created_at = created_at or datetime.now();
        self.description = description;

    def check_password(self, password):
        return User.digest_password(password) == self.password

    def __unicode__(self):
        return "<user %d <%s>>" % (self.uid, self.username)


