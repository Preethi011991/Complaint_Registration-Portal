"""Tests for app.security.rbac."""

import pytest

from app.security.rbac import Permission, Role, check_permission, get_permissions
from app.security.security_errors import UnknownRoleError


# If this failed, a citizen could lose the ability to file complaints,
# leave feedback, or attach evidence to their own complaint.
def test_citizen_has_expected_permissions():
    permissions = get_permissions(Role.CITIZEN)

    assert permissions == {
        Permission.CREATE_COMPLAINT,
        Permission.VIEW_COMPLAINT,
        Permission.SUBMIT_FEEDBACK,
        Permission.UPLOAD_ATTACHMENT,
    }


# If this failed, an officer couldn't do their core job: reviewing and
# progressing the complaints assigned to them.
def test_department_officer_has_expected_permissions():
    permissions = get_permissions(Role.DEPARTMENT_OFFICER)

    assert permissions == {
        Permission.VIEW_COMPLAINT,
        Permission.UPDATE_STATUS,
        Permission.RESOLVE_COMPLAINT,
        Permission.UPLOAD_ATTACHMENT,
    }


# If this failed, a department admin could lose the ability to assign work
# to officers or audit what happened in their department.
def test_department_admin_has_expected_permissions():
    permissions = get_permissions(Role.DEPARTMENT_ADMIN)

    assert permissions == {
        Permission.VIEW_COMPLAINT,
        Permission.UPDATE_STATUS,
        Permission.ASSIGN_COMPLAINT,
        Permission.RESOLVE_COMPLAINT,
        Permission.UPLOAD_ATTACHMENT,
        Permission.VIEW_AUDIT_LOGS,
    }


# If this failed, the system admin could be locked out of user management
# or auditing, or worse, lose the intended "can do everything" guarantee.
def test_system_admin_has_all_permissions():
    permissions = get_permissions(Role.SYSTEM_ADMIN)

    assert permissions == set(Permission)


# If this failed, a citizen could mark their own complaint (or anyone
# else's) as resolved/closed without any staff review.
def test_citizen_is_denied_update_status():
    assert check_permission(Role.CITIZEN, Permission.UPDATE_STATUS) is False


# If this failed, a citizen could assign complaints to staff members,
# something only management should control.
def test_citizen_is_denied_assign_complaint():
    assert check_permission(Role.CITIZEN, Permission.ASSIGN_COMPLAINT) is False


# If this failed, a citizen could unilaterally close out any complaint,
# bypassing the staff resolution workflow entirely.
def test_citizen_is_denied_resolve_complaint():
    assert check_permission(Role.CITIZEN, Permission.RESOLVE_COMPLAINT) is False


# If this failed, a citizen could read the portal's security audit trail,
# exposing sensitive records of staff and system activity.
def test_citizen_is_denied_view_audit_logs():
    assert check_permission(Role.CITIZEN, Permission.VIEW_AUDIT_LOGS) is False


# If this failed, a citizen could create, modify, or delete other users'
# accounts — a full privilege escalation to admin-level control.
def test_citizen_is_denied_manage_users():
    assert check_permission(Role.CITIZEN, Permission.MANAGE_USERS) is False


# If this failed, an unrecognized or misconfigured role could silently be
# treated as "no permissions" instead of surfacing as a configuration bug,
# letting a broken role go unnoticed instead of blocking access loudly.
def test_unknown_role_raises_instead_of_returning_empty_set():
    with pytest.raises(UnknownRoleError):
        get_permissions("NOT_A_REAL_ROLE")


# If this failed, a typo'd or made-up permission name could crash a
# permission check in production instead of safely denying access.
def test_unknown_permission_string_returns_false_instead_of_raising():
    assert check_permission(Role.SYSTEM_ADMIN, "NOT_A_REAL_PERMISSION") is False


# If this failed, a department officer could manage user accounts — a
# privilege escalation well beyond their intended day-to-day role.
def test_system_admin_has_manage_users_but_department_officer_does_not():
    assert check_permission(Role.SYSTEM_ADMIN, Permission.MANAGE_USERS) is True
    assert check_permission(Role.DEPARTMENT_OFFICER, Permission.MANAGE_USERS) is False


# If this failed, a permission could be defined in the enum but never
# actually granted to any role — a permission that exists on paper but is
# unreachable in practice, usually indicating a forgotten mapping entry.
def test_every_permission_is_granted_to_at_least_one_role():
    granted_permissions = set()
    for role in Role:
        granted_permissions |= get_permissions(role)

    assert granted_permissions == set(Permission)
