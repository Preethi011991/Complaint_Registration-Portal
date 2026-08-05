from security import (
    hash_password,
    verify_password,
    generate_jwt,
    verify_jwt,
    validate_input,
    verify_role,
)

# Test Password Hashing
password = "MyPassword123!"

hashed_password, salt = hash_password(password)

print("Hash:", hashed_password)
print("Salt:", salt)

print("Password Verified:",
      verify_password(password, hashed_password, salt))

# Test JWT
token = generate_jwt(
    user_id=1,
    username="preethi",
    role="admin"
)

print("JWT:", token)

payload = verify_jwt(token)

print("Decoded Payload:", payload)

# Test Input Validation
text = "<script>alert('Hack')</script>"

print(validate_input(text))

# Test RBAC
print(verify_role("admin", "admin"))