from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uvicorn

# Configuration
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "a very secret key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Models
class Department(Base):
    __tablename__ = "departments"
    id = Column(Integer, primary_key=True, index=True)
    department_name = Column(String, index=True)
    submitted_by = Column(String)
    updated_at = Column(String)

    students = relationship("Student", back_populates="department")
    courses = relationship("Course", back_populates="department")

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, index=True)
    department_id = Column(Integer, ForeignKey('departments.id'))
    class_id = Column(String, index=True)
    submitted_by = Column(String)
    updated_at = Column(String)

    department = relationship("Department", back_populates="students")
    attendance_logs = relationship("AttendanceLog", back_populates="student")

class Course(Base):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True, index=True)
    course_name = Column(String, index=True)
    department_id = Column(Integer, ForeignKey('departments.id'))
    semester = Column(String)
    lecture_hours = Column(Integer)
    class_id = Column(String, index=True)
    submitted_by = Column(String)
    updated_at = Column(String)

    department = relationship("Department", back_populates="courses")
    attendance_logs = relationship("AttendanceLog", back_populates="course")

class AttendanceLog(Base):
    __tablename__ = "attendance_log"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey('students.id'))
    course_id = Column(Integer, ForeignKey('courses.id'))
    present = Column(Boolean)
    submitted_by = Column(String)
    updated_at = Column(String)

    student = relationship("Student", back_populates="attendance_logs")
    course = relationship("Course", back_populates="attendance_logs")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    full_name = Column(String)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    submitted_by = Column(String)
    updated_at = Column(String)

# Initialize DB
def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(username="admin").first()
        if not user:
            hashed_password = pwd_context.hash("admin123")
            admin_user = User(
                username="admin",
                email="admin@example.com",
                full_name="Admin User",
                hashed_password=hashed_password,
                type="admin"
            )
            db.add(admin_user)
            db.commit()
            print("Admin user created. Username: 'admin' with password: 'admin123'")
    finally:
        db.close()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility for hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None


# Pydantic schemas for CRUD operations on Department
class DepartmentBase(BaseModel):
    department_name: str

class DepartmentCreate(DepartmentBase):
    pass

class Department(DepartmentBase):
    id: int
    submitted_by: str
    updated_at: str

    class Config:
        orm_mode = True
      
class StudentBase(BaseModel):
  full_name: str
  department_id: int
  class_id: str

class StudentCreate(StudentBase):
  pass

class StudentUpdate(StudentBase):
  pass

class StudentOut(StudentBase):
  id: int
  submitted_by: str
  updated_at: str

  class Config:
      orm_mode = True

class CourseBase(BaseModel):
  course_name: str
  department_id: int
  semester: str
  lecture_hours: int
  class_id: str

class CourseCreate(CourseBase):
  pass

class CourseUpdate(CourseBase):
  pass

class CourseOut(CourseBase):
  id: int
  submitted_by: str
  updated_at: str

  class Config:
      orm_mode = True

class AttendanceLogBase(BaseModel):
  student_id: int
  course_id: int
  present: bool

class AttendanceLogCreate(AttendanceLogBase):
  pass

class AttendanceLogUpdate(AttendanceLogBase):
  pass

class AttendanceLogOut(AttendanceLogBase):
  id: int
  submitted_by: str
  updated_at: str

  class Config:
      orm_mode = True

class UserBase(BaseModel):
  username: str
  email: str
  full_name: str
  type: str

class UserCreate(UserBase):
  password: str

class UserUpdate(UserBase):
  pass

class UserOut(UserBase):
  id: int
  submitted_by: str
  updated_at: str

  class Config:
      orm_mode = True


# Create a token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Authenticate user
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if user and pwd_context.verify(password, user.hashed_password):
        return user
    return False

# Get current user
async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=Token)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return create_access_token(data={"sub": user.username})

# CRUD operations for Course
@app.post("/courses/", response_model=CourseOut)
def create_course(course: CourseCreate, db: Session = Depends(get_db)):
    db_course = Course(**course.dict())
    db.add(db_course)
    db.commit()
    db.refresh(db_course)
    return db_course

@app.get("/courses/", response_model=List[CourseOut])
def read_courses(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    courses = db.query(Course).offset(skip).limit(limit).all()
    return courses

@app.get("/courses/{course_id}", response_model=CourseOut)
def read_course(course_id: int, db: Session = Depends(get_db)):
    course = db.query(Course).filter(Course.id == course_id).first()
    if course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    return course

@app.put("/courses/{course_id}", response_model=CourseOut)
def update_course(course_id: int, course: CourseUpdate, db: Session = Depends(get_db)):
    db_course = db.query(Course).filter(Course.id == course_id).first()
    if db_course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    for var, value in vars(course).items():
        setattr(db_course, var, value) if value else None
    db.commit()
    db.refresh(db_course)
    return db_course

@app.delete("/courses/{course_id}", response_model=CourseOut)
def delete_course(course_id: int, db: Session = Depends(get_db)):
    db_course = db.query(Course).filter(Course.id == course_id).first()
    if db_course is None:
        raise HTTPException(status_code=404, detail="Course not found")
    db.delete(db_course)
    db.commit()
    return db_course

# CRUD operations for AttendanceLog
@app.post("/attendance_logs/", response_model=AttendanceLogOut)
def create_attendance_log(attendance_log: AttendanceLogCreate, db: Session = Depends(get_db)):
    db_attendance_log = AttendanceLog(**attendance_log.dict())
    db.add(db_attendance_log)
    db.commit()
    db.refresh(db_attendance_log)
    return db_attendance_log

@app.get("/attendance_logs/", response_model=List[AttendanceLogOut])
def read_attendance_logs(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    attendance_logs = db.query(AttendanceLog).offset(skip).limit(limit).all()
    return attendance_logs

@app.get("/attendance_logs/{attendance_log_id}", response_model=AttendanceLogOut)
def read_attendance_log(attendance_log_id: int, db: Session = Depends(get_db)):
    attendance_log = db.query(AttendanceLog).filter(AttendanceLog.id == attendance_log_id).first()
    if attendance_log is None:
        raise HTTPException(status_code=404, detail="Attendance log not found")
    return attendance_log

@app.put("/attendance_logs/{attendance_log_id}", response_model=AttendanceLogOut)
def update_attendance_log(attendance_log_id: int, attendance_log: AttendanceLogUpdate, db: Session = Depends(get_db)):
    db_attendance_log = db.query(AttendanceLog).filter(AttendanceLog.id == attendance_log_id).first()
    if db_attendance_log is None:
        raise HTTPException(status_code=404, detail="Attendance log not found")
    for var, value in vars(attendance_log).items():
        setattr(db_attendance_log, var, value) if value else None
    db.commit()
    db.refresh(db_attendance_log)
    return db_attendance_log

@app.delete("/attendance_logs/{attendance_log_id}", response_model=AttendanceLogOut)
def delete_attendance_log(attendance_log_id: int, db: Session = Depends(get_db)):
    db_attendance_log = db.query(AttendanceLog).filter(AttendanceLog.id == attendance_log_id).first()
    if db_attendance_log is None:
        raise HTTPException(status_code=404, detail="Attendance log not found")
    db.delete(db_attendance_log)
    db.commit()
    return db_attendance_log

# CRUD operations for User
@app.post("/users/", response_model=UserOut)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(**user.dict(), hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/", response_model=List[UserOut])
def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@app.get("/users/{user_id}", response_model=UserOut)
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    for var, value in vars(user).items():
        setattr(db_user, var, value) if value else None
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", response_model=UserOut)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return db_user







# Run init_db when starting the app
init_db()

# Run the app
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
