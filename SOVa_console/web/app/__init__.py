from flask import Flask, flash
from flask_admin import Admin
from flask_login import LoginManager
from flask_bcrypt import generate_password_hash

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql+psycopg2://postgres:postgres@sova_db_1/sova"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['BUNDLE_ERRORS'] = True
    app.secret_key="anystringhere"
    
    from .models import db
    db.init_app(app)

    from .resources import blueprint as api
    app.register_blueprint(api, url_prefix="/v1")

    admin = Admin(app, name='SOVa', template_mode='bootstrap3')
    login_manager.init_app(app)
    from .models.models import SIB
    from .models.models import User
    from .view_models.SIB import SIBModelView
    from .view_models.user import UserModelView
    
    admin.add_view(SIBModelView(SIB, db.session, u'События информационной безопасности'))
    admin.add_view(UserModelView(User, db.session, 'Пользователи'))

    with app.app_context():
        # try:
        #     db.drop_all()
        # except:
        #     pass
        db.create_all()
        try:    
            password = 'admin'
            username = 'admin'
            
            newuser = User(
                username=username,
                password=generate_password_hash(password).decode('utf-8'),
            )
            db.session()
            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
        except:
            pass
    
    return app

if __name__ == '__main__':
    create_app()
