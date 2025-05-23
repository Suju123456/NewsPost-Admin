# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from email.policy import default
from apps import db
from sqlalchemy.exc import SQLAlchemyError
from apps.exceptions.exception import InvalidUsage
from datetime import datetime
from sqlalchemy.orm import relationship
from enum import Enum



class Product(db.Model):

    __tablename__ = 'products'

    id            = db.Column(db.Integer,      primary_key=True)
    name          = db.Column(db.String(128),  nullable=False)
    info          = db.Column(db.Text,         nullable=True)
    price         = db.Column(db.Integer,      nullable=False)
    
    def __init__(self, **kwargs):
        super(Product, self).__init__(**kwargs)

    def __repr__(self):
        return f"{self.name} / ${self.price}"

    @classmethod
    def find_by_id(cls, _id: int) -> "Product":
        return cls.query.filter_by(id=_id).first() 

    @classmethod
    def get_list(cls):
        return cls.query.all()

    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)

    def delete(self) -> None:
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            db.session.close()
            error = str(e.__dict__['orig'])
            raise InvalidUsage(error, 422)
        return
    

class NewsPost(db.Model):
    __tablename__ = "news_posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author = db.relationship('Users', back_populates='posts')
    status = db.Column(db.Boolean, nullable=False, default=False)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=False)
    categories = db.relationship('Category', back_populates='news_posts' , lazy= True)

    banner_image = db.Column(db.String(100), nullable=True)  # Stores file path

    content_images= db.relationship("ContentImage", back_populates="news_posts", cascade="all, delete-orphan")
    
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)



class ContentImage(db.Model):
    __tablename__ = "content_images"

    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(100), nullable=False)
    #position = db.Column(db.Integer)  # For ordering images in content
    news_post_id = db.Column(
        db.Integer, db.ForeignKey("news_posts.id", name="fk_content_image_post")
    )       
    news_posts = db.relationship("NewsPost", back_populates="content_images", lazy=True)

    position = db.Column(db.Integer)


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    # Define the Post model with the many-to-many relationship
    
    news_posts = db.relationship('NewsPost', back_populates='categories', lazy=True)


