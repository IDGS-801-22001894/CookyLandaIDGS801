from werkzeug.security import generate_password_hash

from werkzeug.security import generate_password_hash

print("Hashes generados:")
print(f"Cliente123_: {generate_password_hash('Cliente123_')}")
print(f"Vendedor123_: {generate_password_hash('Vendedor123_')}")
print(f"Cocinero123_: {generate_password_hash('Cocinero123_')}")
print(f"Admin123_: {generate_password_hash('Admin123_')}")


    