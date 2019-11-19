def get_current_user_roles(current_user):
    _roles = []
    if hasattr(current_user, "roles"):
        for role in current_user.roles:
            try:
                int(role.name)
            except ValueError:
                continue
            _roles.append(role.name)
    return _roles
