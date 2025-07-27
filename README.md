# Banking-REST-API-with-FastAPI-JWT-Authentication-and-MySQL

## Project Description:
This is a FastAPI-based RESTful Bank API that supports secure user registration, account management, and transaction handling. The system uses JWT authentication and MySQL for persistent storage. It's built as a single-file teaching sample and ideal for learning how to use FastAPI with modern tooling and best practices.

## Features:
1. User Authentication using JWT (login & register)
2. Bank Account CRUD APIs with initial deposit and balance update
3. Transaction APIs for deposits and withdrawals
4. User-specific access control: users can access only their own accounts and transactions
5. Built with SQLAlchemy 2.0, Pydantic, and FastAPI
6. Interactive Swagger UI at /docs with dark theme
7. Healthcheck endpoint at /health
---
## Tech Stack:
1. Python 3.13  
2. Django 4.2  
3. Django REST Framework  
4. Simple JWT (for Authentication)
5. Passlib (bcrypt)
6. Pydantic + EmailValidator
7. MySQL Database  

---
## My SQL DataBase
```bash
CREATE DATABASE BANK;
use BANK;
CREATE USER 'bankuser'@'localhost' IDENTIFIED BY 'BankPass123';
GRANT ALL PRIVILEGES ON BANK.* TO 'bankuser'@'localhost';

ALTER USER 'bankuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'BankPass123';
FLUSH PRIVILEGES;
```
## Setup Instructions
### 1️. Clone the Repository
```bash
git clone https://github.com/k-venky-reddy/Django_Admin_Portal.git
cd project-management-system
```
### 2️. Create and Activate Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate  # On Windows
```
### 3️. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run bank_api_fastapi.py
```bash
uvicorn bank_api_fastapi:app --reload
```
Now visit [[http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/docs)) 
---

## Contact Me

Hi, I'm Venkatesh Reddy. I developed this project to demonstrate my skills in authentication, API design, and user-specific data handling.
If you need any further information or assistance, feel free to contact me.

- Reach me at: kvenkyreddy113@gmail.com
