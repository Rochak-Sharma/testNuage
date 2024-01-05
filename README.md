# Attendance Management System API

This project is a RESTful API for an Attendance Management System built with FastAPI. It provides CRUD operations for managing departments, courses, students, attendance records, and users.

## Features

- FastAPI framework, high performance, easy to learn, fast to code, ready for production
- RESTful API with CRUD operations for Departments, Students, Courses, Attendance Logs, and Users
- Automatic admin user creation on database initialization
- Basic authentication with hashed passwords
- Token-based user authentication with OAuth2 and JWT tokens

## Installation

To set up this project, follow these steps:

1. Clone the repository to your local machine.
2. Create a virtual environment:

```sh
python3 -m venv venv

venv\Scripts\activate

Run the application

uvicorn main:app --reload

The API will be available at http://127.0.0.1:8000.

Usage
You can test the API endpoints using a tool like curl or Postman, or by visiting the automatically generated Swagger UI at http://127.0.0.1:8000/docs.



