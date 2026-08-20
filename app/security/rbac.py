"""Role-based access control: roles, permissions, policy checks."""

from __future__ import annotations

from enum import Enum

from app.security.security_errors import UnknownRoleError


class Role(str, Enum):
    """User roles recognized by the portal."""

    CITIZEN = "CITIZEN"
    DEPARTMENT_OFFICER = "DEPARTMENT_OFFICER"
    DEPARTMENT_ADMIN = "DEPARTMENT_ADMIN"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


class Permission(str, Enum):
    """Actions that can be permitted or denied within the portal."""

    CREATE_COMPLAINT = "CREATE_COMPLAINT"
    VIEW_COMPLAINT = "VIEW_COMPLAINT"
    UPDATE_STATUS = "UPDATE_STATUS"
    ASSIGN_COMPLAINT = "ASSIGN_COMPLAINT"
    RESOLVE_COMPLAINT = "RESOLVE_COMPLAINT"
    SUBMIT_FEEDBACK = "SUBMIT_FEEDBACK"
    UPLOAD_ATTACHMENT = "UPLOAD_ATTACHMENT"
    VIEW_AUDIT_LOGS = "VIEW_AUDIT_LOGS"
    MANAGE_USERS = "MANAGE_USERS"


# This is a ROLE-LEVEL check only: it answers "can this role ever perform
# this action, in principle." It does NOT answer "can this specific user
# perform this action on this specific complaint" — ownership and
# department-scoped access (e.g. "can this citizen view THIS complaint,"
# "can this officer act on complaints outside their department") are
# checked separately, in resource_access.py. A permission granted here is
# necessary but not sufficient for accessing a specific resource.
#
# This dict is the single source of truth for role -> permission mapping.
# No other module may hardcode or duplicate this logic.
_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.CITIZEN: {
        Permission.CREATE_COMPLAINT,
        Permission.VIEW_COMPLAINT,
        Permission.SUBMIT_FEEDBACK,
        Permission.UPLOAD_ATTACHMENT,
    },
    Role.DEPARTMENT_OFFICER: {
        Permission.VIEW_COMPLAINT,
        Permission.UPDATE_STATUS,
        Permission.RESOLVE_COMPLAINT,
        Permission.UPLOAD_ATTACHMENT,
    },
    Role.DEPARTMENT_ADMIN: {
        Permission.VIEW_COMPLAINT,
        Permission.UPDATE_STATUS,
        Permission.ASSIGN_COMPLAINT,
        Permission.RESOLVE_COMPLAINT,
        Permission.UPLOAD_ATTACHMENT,
        Permission.VIEW_AUDIT_LOGS,
    },
    Role.SYSTEM_ADMIN: {
        Permission.CREATE_COMPLAINT,
        Permission.VIEW_COMPLAINT,
        Permission.UPDATE_STATUS,
        Permission.ASSIGN_COMPLAINT,
        Permission.RESOLVE_COMPLAINT,
        Permission.SUBMIT_FEEDBACK,
        Permission.UPLOAD_ATTACHMENT,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_USERS,
    },
}


def _require_known_role(role: Role) -> set[Permission]:
    try:
        return _ROLE_PERMISSIONS[role]
    except KeyError as exc:
        raise UnknownRoleError(
            f"Role {role!r} has no entry in the RBAC permission mapping. "
            "Failing closed: no permissions can be assumed for an unknown role."
        ) from exc


def get_permissions(role: Role) -> set[Permission]:
    """Return the full set of permissions granted to a role.

    Args:
        role: The role to look up.

    Returns:
        The set of Permissions granted to this role.

    Raises:
        UnknownRoleError: If role has no entry in the mapping. This
            fails closed (loudly) rather than returning an empty set,
            since a silent empty set could be mistaken for "no
            permissions" instead of "this role was never configured."
    """
    return set(_require_known_role(role))


def get_role_permissions(role: Role) -> set[Permission]:
    """Alias for get_permissions, provided for call-site readability.

    See get_permissions for full documentation.
    """
    return get_permissions(role)


def check_permission(role: Role, permission: Permission) -> bool:
    """Check whether a role is granted a specific permission.

    Args:
        role: The role to check.
        permission: The permission being requested.

    Returns:
        True only if permission is explicitly present in role's granted
        set. Anything not explicitly granted defaults to False — there
        is no implicit or wildcard grant.

    Raises:
        UnknownRoleError: If role has no entry in the mapping.
    """
    return permission in _require_known_role(role)
