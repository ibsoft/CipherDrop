from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, HiddenField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional

EXPIRY_CHOICES = [
    ("15m", "15 minutes"),
    ("1h", "1 hour"),
    ("12h", "12 hours"),
    ("1d", "1 day"),
    ("3d", "3 days"),
    ("7d", "7 days (max)"),
]


class SecretForm(FlaskForm):
    form_name = HiddenField(default="secret")
    secret_text = TextAreaField(
        "Secret text",
        validators=[DataRequired(message="Secret cannot be empty"), Length(max=8000)],
        render_kw={"rows": 5},
    )
    password = PasswordField(
        "Password (optional)",
        validators=[Optional(), Length(min=8, max=128, message="Use 8-128 characters")],
    )
    expires_in = SelectField("Expires in", validators=[DataRequired()], choices=EXPIRY_CHOICES)
    burn_after_read = BooleanField("Burn after reading", default=True)
    submit = SubmitField("Create secure secret")


class FileSecretForm(FlaskForm):
    form_name = HiddenField(default="file")
    file = FileField("Secure file", validators=[FileRequired(message="Please choose a file")])
    password = PasswordField(
        "Password (optional)",
        validators=[Optional(), Length(min=8, max=128, message="Use 8-128 characters")],
    )
    expires_in = SelectField("Expires in", validators=[DataRequired()], choices=EXPIRY_CHOICES)
    burn_after_read = BooleanField("Burn after reading", default=True)
    submit = SubmitField("Create secure file link")


class PasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[Optional(), Length(min=0, max=128)])
    submit = SubmitField("Unlock")
