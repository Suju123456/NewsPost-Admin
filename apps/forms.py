from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField,MultipleFileField, FileField
from flask_wtf.file import FileAllowed, FileRequired
from wtforms.validators import DataRequired
from wtforms.widgets import TextArea
from apps.models import Category

# Create a Posts Form                       
class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    status = SelectField('Status', choices=[
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived')
    ])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = SelectField("Author",coerce=int, validators=[DataRequired()])
    categories= SelectField('Category',coerce=int,validators=[DataRequired()])
    
    banner_image = FileField('Image', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    content_images = MultipleFileField('Content Images', validators=[
    FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'webp'], 'Images only!')
    ])
    submit = SubmitField("Submit")
    
    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        # Populate the dropdown with categories from the database
        self.categories.choices = [
            (c.id, c.name) for c in Category.query.order_by(Category.name)
        ]

    

    
