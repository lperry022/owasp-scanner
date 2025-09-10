import sqlite3
import hashlib
import requests
import yaml
import pickle
import subprocess
from flask import Flask, Response

# ---------- A05: Security Misconfiguration ----------
SECRET_KEY = "changeme"           
ALLOWED_HOSTS = ['*']              
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False         

# ---------- A03: Sensitive Data Exposure ----------
password = "SuperSecret123"       
api_key = "sk_test_123456"         
hashlib.md5(b"weak")               

# ---------- A07: Identification and Authentication Failures ----------
username = "admin"                 
default_password = "password"      
requests.get("https://example.com", verify=False)  

app = Flask(__name__)

# ---------- A02: Broken Access Control ----------
@app.route("/admin")
def admin_panel():
    resp = Response("admin panel")
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/login")
def login_page():
    print("login attempt for user")  
    return "login page"

# ---------- A04: Insecure Design ----------


# ---------- A06: Vulnerable and Outdated Components ----------
requirements_block = """
flask==0.12
django==1.11
"""

# ---------- A08: Software and Data Integrity Failures ----------
user_code = "1 + 2"
result = eval(user_code)                     
data = yaml.load("key: value")               
with open("tmp.bin", "wb") as fh:
    pickle.dump({"x": 1}, fh)                
with open("tmp.bin", "rb") as fh:
    obj = pickle.load(fh)                    
subprocess.run("echo hi", shell=True)        

# ---------- A09: Security Logging and Monitoring Failures ----------
try:
    raise ValueError("x")
except:
    print("error:", default_password)        

# ---------- A10: SSRF ----------
url = input("Enter URL: ")
requests.get(url)                             

# ---------- A01: Injection ----------
user_input = input("Enter your username: ")
query = "SELECT * FROM users WHERE username = '" + user_input + "'"

conn = sqlite3.connect("example.db")
cursor = conn.cursor()
cursor.execute(query)  

if __name__ == "__main__":
    app.run(debug=True)
