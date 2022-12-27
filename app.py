import os

from flask import (Flask, abort, current_app, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_admin import Admin
from flask_admin import helpers as admin_helpers
from flask_admin.contrib import sqla
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask_migrate import Migrate
from flask_security import (RoleMixin, Security, SQLAlchemyUserDatastore,
                            UserMixin, auth_required, hash_password,
                            login_required, roles_required)
from flask_security.models import fsqla_v3 as fsqla
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True

# Generate a nice key using secrets.token_urlsafe()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
# Generate a good salt using: secrets.SystemRandom().getrandbits(128)
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')

# have session and remember cookie be samesite (flask/flask_login)
app.config["REMEMBER_COOKIE_SAMESITE"] = "strict"
app.config["SESSION_COOKIE_SAMESITE"] = "strict"

# Use an in-memory db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///codecraft.db'
# As of Flask-SQLAlchemy 2.4.0 it is easy to pass in options directly to the
# underlying engine. This option makes sure that DB connections from the
# pool are still valid. Important for entire application since
# many DBaaS options automatically close idle connections.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECURITY_REGISTER_URL"] = "/create_account"

app.config["FLASK_ADMIN_SWATCH"] = "flatly"

# Create database connection object
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define models
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return "Role: %r" % self.name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship(
        "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
    )
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    contact_revert = db.relationship("Contact", backref="contact_reverted", lazy=True)

    def __repr__(self):
        return "<Email: %r>" % self.email


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sheet_name = db.Column(db.String(255))
    email_to_share = db.Column(db.String(255))
    reason_for_sms = db.Column(db.Text())
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now()
    )

    def __repr__(self):
        return "<Sheet Name: %r - Date: %r>" % (self.sheet_name, self.created_on)


class ContactTextForm(FlaskForm):
    name_of_contact = StringField("Sheet Name", validators=[DataRequired()])
    email_to_share = StringField('Email', validators=[Email()])
    reason_for_contact = TextAreaField(
        "Reason for Contacting us", validators=[DataRequired()]
    )


class MarketingTextForm(FlaskForm):
    marketing_tag = StringField("Sheet Name", validators=[DataRequired()])
    marketing_description = TextAreaField(
        "Marketing waifu", validators=[DataRequired()]
    )


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create customized model view class


class MyModelView(sqla.ModelView):
    def is_accessible(self):
        return (
            current_user.is_active
            and current_user.is_authenticated
            and current_user.has_role("superuser")
        )

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for("security.login", next=request.url))


admin = Admin(app, name="Site Access", template_mode="bootstrap3")
admin.add_view(MyModelView(Role, db.session))
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Contact, db.session))

# Create a user to test with
@app.before_first_request
def create_user():
    db.create_all()

    user_role = Role(name="user")
    super_user_role = Role(name="superuser")
    db.session.add(user_role)
    db.session.add(super_user_role)

    user_datastore.create_user(
        email="duncanireri@gmail.com",
        password=hash_password("slowpassword"),
        roles=[user_role, super_user_role],
    )
    db.session.commit()


@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for,
    )


# Views
@app.route("/", methods=["GET", "POST"])
def home():
    main_form = ContactTextForm()
    return render_template(
        "index.html", main_form=main_form
    )


@app.route("/create_account", methods=["GET"])
@login_required
@roles_required("staff", "superuser")
def register():
    return render_template("security/register_user.html")


if __name__ == "__main__":
    app.run()
