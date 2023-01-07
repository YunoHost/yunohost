from yunohost.interface import Interface

from yunohost.user import app as user_app


def create_interface():
    app = Interface(root=True)
    app.add(user_app)

    return app.instance
