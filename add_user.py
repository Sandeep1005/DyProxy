import yaml
import bcrypt
import os

auth_file = "auth.yaml"

def load_auth():
    if not os.path.exists(auth_file):
        return {"users": {}}
    with open(auth_file, "r") as file:
        return yaml.safe_load(file) or {"users": {}}

def save_auth(data):
    with open(auth_file, "w") as file:
        yaml.safe_dump(data, file)

def add_user():
    username = input("Enter new username: ")
    password = input("Enter new password: ")
    
    auth_data = load_auth()
    
    if username in auth_data["users"]:
        print("Username already exists!")
        return
    
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    auth_data["users"][username] = hashed_password
    save_auth(auth_data)
    print("User added successfully!")

if __name__ == "__main__":
    add_user()
