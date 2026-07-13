from functools import wraps
from typing import Callable

from flask import flash, g, redirect, session, url_for

from repositories import get_user_by_id


def login_user(user: dict, remember: bool = False) -> None:
    session.clear()
    session['user_id'] = user['id']
    session['user_roles'] = user.get('roles', [])
    session.permanent = remember


def logout_user() -> None:
    session.clear()


def load_current_user() -> None:
    user_id = session.get('user_id')
    if not user_id:
        g.current_user = None
        return

    user = get_user_by_id(int(user_id))
    if not user:
        session.clear()
        g.current_user = None
        return
    g.current_user = user


def login_required(view: Callable):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not getattr(g, 'current_user', None):
            flash('Please sign in first.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*required_roles: str):
    def decorator(view: Callable):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            current_user = getattr(g, 'current_user', None)
            if not current_user:
                flash('Please sign in first.', 'warning')
                return redirect(url_for('login'))

            user_roles = set(current_user.get('roles', []))
            if not any(role in user_roles for role in required_roles):
                flash('You do not have access to this page.', 'danger')
                return redirect(url_for('index'))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator
