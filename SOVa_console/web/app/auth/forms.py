from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, ValidationError
from wtforms.validators import InputRequired, Email, Length, Optional, Regexp, EqualTo
from ..models.models import User

class login_form(FlaskForm):
    class Meta:
        csrf = False
        
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=72)])
    # Placeholder labels to enable form rendering
    username = StringField(
        validators=[Optional()]
    )
    
class register_form(FlaskForm):
    class Meta:
        csrf = False
        
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 32, message="Please provide a valid name"),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    password = PasswordField(validators=[InputRequired(), Length(4, 72)])
    cpassword = PasswordField(
        validators=[
            InputRequired(),
            Length(4, 72),
            EqualTo("password", message="Passwords must match !"),
        ]
    )

    def validate_uname(self, uname):
        if User.query.filter_by(username=uname.data).first():
            raise ValidationError("Username already taken!")