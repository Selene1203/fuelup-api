from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import pymysql
import pymysql.cursors
import os
import hashlib
import jwt
import datetime
import math
import csv
import io

# =============================================================================
# APP SETUP
# =============================================================================
app = FastAPI(title="FuelUp API")

@app.on_event("startup")
def create_missing_tables():
    try:
        url = os.environ.get("RAILWAY_DATABASE_URL", "")
        url = url.replace("mysql://", "")
        user_pass, rest = url.split("@", 1)
        user, password = user_pass.split(":", 1)
        host_port, dbname = rest.rsplit("/", 1)
        host, port = (host_port.rsplit(":", 1) if ":" in host_port else (host_port, "3306"))
        conn = pymysql.connect(host=host, port=int(port), user=user, password=password,
                               database=dbname, cursorclass=pymysql.cursors.DictCursor, ssl={"ssl": {}})
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS Review (
                    review_id  INT AUTO_INCREMENT PRIMARY KEY,
                    user_id    INT NOT NULL,
                    station_id INT NOT NULL,
                    rating     INT CHECK (rating BETWEEN 1 AND 5),
                    comment    TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id)    REFERENCES User(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (station_id) REFERENCES PetrolStation(station_id) ON DELETE CASCADE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS Favorite (
                    favorite_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id     INT NOT NULL,
                    station_id  INT NOT NULL,
                    saved_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id)    REFERENCES User(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (station_id) REFERENCES PetrolStation(station_id) ON DELETE CASCADE
                )
            """)
            conn.commit()
        conn.close()
        print("✅ Tables verified/created successfully")
    except Exception as e:
        print(f"⚠️ Startup table check failed: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

SECRET_KEY = os.environ.get("JWT_SECRET", "fuelup-secret-key-change-in-production")
DATABASE_URL = os.environ.get("RAILWAY_DATABASE_URL", "")

# =============================================================================
# DATABASE
# =============================================================================
def get_db():
    url = DATABASE_URL
    # Parse mysql://user:pass@host:port/db
    url = url.replace("mysql://", "")
    user_pass, rest = url.split("@", 1)
    user, password = user_pass.split(":", 1)
    host_port, dbname = rest.rsplit("/", 1)
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        port = int(port)
    else:
        host = host_port
        port = 3306

    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=dbname,
        cursorclass=pymysql.cursors.DictCursor,
        ssl={"ssl": {}},
        connect_timeout=10,
    )
    try:
        yield conn
    finally:
        conn.close()

# =============================================================================
# AUTH HELPERS
# =============================================================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(user_id: int, role: str, name: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "name": name,
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(credentials.credentials)

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.asin(math.sqrt(a))

# =============================================================================
# MODELS
# =============================================================================
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    preferred_theme: Optional[str] = None
    preferred_fuel: Optional[str] = None
    distance_unit: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class StationCreateRequest(BaseModel):
    name: str
    latitude: float
    longitude: float
    address: Optional[str] = None
    city: Optional[str] = None
    country: str = "Lesotho"
    phone: Optional[str] = None
    opening_hours: Optional[str] = "06:00 - 22:00"

class StationUpdateRequest(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    phone: Optional[str] = None
    opening_hours: Optional[str] = None
    is_verified: Optional[bool] = None

class PriceUpdateRequest(BaseModel):
    fuel_type_id: int
    price_per_liter: float

class ReviewCreateRequest(BaseModel):
    station_id: int
    rating: int
    comment: Optional[str] = None

class ReviewUpdateRequest(BaseModel):
    rating: Optional[int] = None
    comment: Optional[str] = None

# =============================================================================
# HEALTH
# =============================================================================
@app.get("/api/health")
def health(db=Depends(get_db)):
    try:
        with db.cursor() as cur:
            cur.execute("SHOW TABLES")
            tables = [list(row.values())[0] for row in cur.fetchall()]
        return {"status": "ok", "db": "railway_mysql", "tables": tables}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# =============================================================================
# AUTH
# =============================================================================
@app.post("/api/auth/register")
def register(body: RegisterRequest, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT user_id FROM User WHERE email = %s", (body.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")
        cur.execute(
            "INSERT INTO User (name, email, password_hash) VALUES (%s, %s, %s)",
            (body.name, body.email, hash_password(body.password))
        )
        db.commit()
        user_id = cur.lastrowid
    token = create_token(user_id, "user", body.name, body.email)
    return {"token": token, "role": "user", "name": body.name, "email": body.email}

@app.post("/api/auth/login")
def login(body: LoginRequest, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM User WHERE email = %s", (body.email,))
        user = cur.fetchone()

    # Check regular user
    if user and user["password_hash"] == hash_password(body.password):
        # Check if this user is also a business admin
        with db.cursor() as cur:
            cur.execute("SELECT admin_id FROM BusinessAdmin WHERE contact_email = %s AND is_active = TRUE", (body.email,))
            admin = cur.fetchone()
        role = "admin" if admin else "user"
        token = create_token(user["user_id"], role, user["name"], user["email"])
        return {"token": token, "role": role, "name": user["name"], "email": user["email"]}

    # Check business admin by secret code (email = contact_email, password = secret_code)
    with db.cursor() as cur:
        cur.execute(
            "SELECT * FROM BusinessAdmin WHERE contact_email = %s AND secret_code = %s AND is_active = TRUE",
            (body.email, body.password)
        )
        admin = cur.fetchone()
    if admin:
        with db.cursor() as cur:
            cur.execute("UPDATE BusinessAdmin SET last_login = NOW() WHERE admin_id = %s", (admin["admin_id"],))
            db.commit()
        token = create_token(admin["admin_id"], "admin", admin["business_name"], admin["contact_email"])
        return {"token": token, "role": "admin", "name": admin["business_name"], "email": admin["contact_email"]}

    raise HTTPException(status_code=401, detail="Invalid email or password")

@app.get("/api/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return current_user

# =============================================================================
# STATIONS
# =============================================================================
def station_with_prices(station, db):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ft.fuel_name, sft.price_per_liter, sft.is_available, sft.last_updated
            FROM StationFuelType sft
            JOIN FuelType ft ON ft.fuel_id = sft.fuel_type_id
            WHERE sft.station_id = %s
        """, (station["station_id"],))
        prices = cur.fetchall()
        cur.execute("""
            SELECT COUNT(*) as total, AVG(rating) as avg_rating
            FROM Review WHERE station_id = %s
        """, (station["station_id"],))
        stats = cur.fetchone()
    station["prices"] = prices
    station["review_count"] = stats["total"] if stats else 0
    station["avg_rating"] = round(float(stats["avg_rating"]), 1) if stats and stats["avg_rating"] else station.get("rating", 0)
    cheapest = min((p["price_per_liter"] for p in prices if p["is_available"] and p["price_per_liter"]), default=None)
    station["cheapest_price"] = float(cheapest) if cheapest else None
    return station

@app.get("/api/stations")
def list_stations(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM PetrolStation ORDER BY name")
        stations = cur.fetchall()
    return [station_with_prices(s, db) for s in stations]

@app.get("/api/stations/nearby")
def nearby_stations(lat: float, lng: float, radius: float = 50, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM PetrolStation")
        stations = cur.fetchall()
    result = []
    for s in stations:
        dist = haversine(lat, lng, float(s["latitude"]), float(s["longitude"]))
        if dist <= radius:
            s = station_with_prices(s, db)
            s["distance_km"] = round(dist, 2)
            result.append(s)
    result.sort(key=lambda x: x["distance_km"])
    return result

@app.get("/api/stations/cheapest")
def cheapest_station(lat: float, lng: float, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ps.*, MIN(sft.price_per_liter) as min_price
            FROM PetrolStation ps
            JOIN StationFuelType sft ON sft.station_id = ps.station_id
            JOIN FuelType ft ON ft.fuel_id = sft.fuel_type_id
            WHERE ft.fuel_name = '95' AND sft.is_available = TRUE
            GROUP BY ps.station_id
        """)
        stations = cur.fetchall()
    result = []
    for s in stations:
        dist = haversine(lat, lng, float(s["latitude"]), float(s["longitude"]))
        if dist <= 10:
            s["distance_km"] = round(dist, 2)
            result.append(s)
    if not result:
        raise HTTPException(status_code=404, detail="No stations with 95 fuel found within 10km")
    return min(result, key=lambda x: x["min_price"])

@app.get("/api/stations/search")
def search_stations(q: str, db=Depends(get_db), current_user: dict = Depends(security)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT * FROM PetrolStation
            WHERE name LIKE %s OR address LIKE %s OR city LIKE %s
        """, (f"%{q}%", f"%{q}%", f"%{q}%"))
        stations = cur.fetchall()
    # Log search if user is authenticated
    if current_user and hasattr(current_user, 'credentials'):
        try:
            user = decode_token(current_user.credentials)
            with db.cursor() as cur:
                cur.execute(
                    "INSERT INTO Search (user_id, query_text, results_count) VALUES (%s, %s, %s)",
                    (user["user_id"], q, len(stations))
                )
                db.commit()
        except Exception:
            pass
    return [station_with_prices(s, db) for s in stations]

@app.get("/api/stations/{station_id}")
def get_station(station_id: int, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM PetrolStation WHERE station_id = %s", (station_id,))
        station = cur.fetchone()
    if not station:
        raise HTTPException(status_code=404, detail="Station not found")
    return station_with_prices(station, db)

@app.post("/api/stations")
def create_station(body: StationCreateRequest, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO PetrolStation (name, latitude, longitude, address, city, country, phone, opening_hours)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (body.name, body.latitude, body.longitude, body.address, body.city, body.country, body.phone, body.opening_hours))
        db.commit()
        station_id = cur.lastrowid
    return {"message": "Station created", "station_id": station_id}

@app.put("/api/stations/{station_id}")
def update_station(station_id: int, body: StationUpdateRequest, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    with db.cursor() as cur:
        cur.execute(f"UPDATE PetrolStation SET {set_clause} WHERE station_id = %s", (*fields.values(), station_id))
        db.commit()
    return {"message": "Station updated"}

@app.delete("/api/stations/{station_id}")
def delete_station(station_id: int, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("UPDATE PetrolStation SET is_verified = FALSE WHERE station_id = %s", (station_id,))
        db.commit()
    return {"message": "Station deactivated"}

# =============================================================================
# FUEL PRICES
# =============================================================================
@app.put("/api/prices/{station_id}")
def update_price(station_id: int, body: PriceUpdateRequest, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT id, price_per_liter FROM StationFuelType
            WHERE station_id = %s AND fuel_type_id = %s
        """, (station_id, body.fuel_type_id))
        existing = cur.fetchone()
        if existing:
            cur.execute("""
                UPDATE StationFuelType SET price_per_liter = %s, last_updated = NOW()
                WHERE station_id = %s AND fuel_type_id = %s
            """, (body.price_per_liter, station_id, body.fuel_type_id))
        else:
            cur.execute("""
                INSERT INTO StationFuelType (station_id, fuel_type_id, price_per_liter, is_available)
                VALUES (%s, %s, %s, TRUE)
            """, (station_id, body.fuel_type_id, body.price_per_liter))
        db.commit()
    return {"message": "Price updated"}

@app.get("/api/prices/history/{station_id}")
def price_history(station_id: int, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT sft.*, ft.fuel_name
            FROM StationFuelType sft
            JOIN FuelType ft ON ft.fuel_id = sft.fuel_type_id
            WHERE sft.station_id = %s
            ORDER BY sft.last_updated DESC
        """, (station_id,))
        return cur.fetchall()

@app.get("/api/fueltypes")
def get_fuel_types(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM FuelType")
        return cur.fetchall()

# =============================================================================
# REVIEWS
# =============================================================================
@app.get("/api/reviews/{station_id}")
def get_reviews(station_id: int, db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT r.*, u.name as user_name
            FROM Review r
            JOIN User u ON u.user_id = r.user_id
            WHERE r.station_id = %s
            ORDER BY r.created_at DESC
        """, (station_id,))
        return cur.fetchall()

@app.post("/api/reviews")
def create_review(body: ReviewCreateRequest, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    if not 1 <= body.rating <= 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO Review (user_id, station_id, rating, comment)
            VALUES (%s, %s, %s, %s)
        """, (current_user["user_id"], body.station_id, body.rating, body.comment))
        # Update station average rating
        cur.execute("""
            UPDATE PetrolStation ps SET rating = (
                SELECT AVG(rating) FROM Review WHERE station_id = %s
            ) WHERE station_id = %s
        """, (body.station_id, body.station_id))
        db.commit()
        review_id = cur.lastrowid
    return {"message": "Review created", "review_id": review_id}

@app.put("/api/reviews/{review_id}")
def update_review(review_id: int, body: ReviewUpdateRequest, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM Review WHERE review_id = %s", (review_id,))
        review = cur.fetchone()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review["user_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Cannot edit another user's review")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if fields:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        with db.cursor() as cur:
            cur.execute(f"UPDATE Review SET {set_clause} WHERE review_id = %s", (*fields.values(), review_id))
            db.commit()
    return {"message": "Review updated"}

@app.delete("/api/reviews/{review_id}")
def delete_review(review_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM Review WHERE review_id = %s", (review_id,))
        review = cur.fetchone()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    if review["user_id"] != current_user["user_id"] and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Cannot delete another user's review")
    with db.cursor() as cur:
        cur.execute("DELETE FROM Review WHERE review_id = %s", (review_id,))
        db.commit()
    return {"message": "Review deleted"}

# =============================================================================
# FAVORITES
# =============================================================================
@app.get("/api/favorites")
def get_favorites(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ps.* FROM Favorite f
            JOIN PetrolStation ps ON ps.station_id = f.station_id
            WHERE f.user_id = %s
            ORDER BY f.saved_at DESC
        """, (current_user["user_id"],))
        stations = cur.fetchall()
    return [station_with_prices(s, db) for s in stations]

@app.post("/api/favorites")
def add_favorite(station_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("SELECT * FROM Favorite WHERE user_id = %s AND station_id = %s", (current_user["user_id"], station_id))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Already in favorites")
        cur.execute("INSERT INTO Favorite (user_id, station_id) VALUES (%s, %s)", (current_user["user_id"], station_id))
        db.commit()
    return {"message": "Added to favorites"}

@app.delete("/api/favorites/{station_id}")
def remove_favorite(station_id: int, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("DELETE FROM Favorite WHERE user_id = %s AND station_id = %s", (current_user["user_id"], station_id))
        db.commit()
    return {"message": "Removed from favorites"}

# =============================================================================
# USER
# =============================================================================
@app.get("/api/user/search-history")
def search_history(db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT s.*, ft.fuel_name
            FROM Search s
            LEFT JOIN FuelType ft ON ft.fuel_id = s.fuel_type_id
            WHERE s.user_id = %s
            ORDER BY s.timestamp DESC
            LIMIT 50
        """, (current_user["user_id"],))
        return cur.fetchall()

@app.put("/api/user/profile")
def update_profile(body: UpdateProfileRequest, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    with db.cursor() as cur:
        cur.execute(f"UPDATE User SET {set_clause} WHERE user_id = %s", (*fields.values(), current_user["user_id"]))
        db.commit()
    return {"message": "Profile updated"}

@app.put("/api/user/password")
def change_password(body: ChangePasswordRequest, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    with db.cursor() as cur:
        cur.execute("SELECT password_hash FROM User WHERE user_id = %s", (current_user["user_id"],))
        user = cur.fetchone()
    if not user or user["password_hash"] != hash_password(body.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    with db.cursor() as cur:
        cur.execute("UPDATE User SET password_hash = %s WHERE user_id = %s", (hash_password(body.new_password), current_user["user_id"]))
        db.commit()
    return {"message": "Password changed"}

# =============================================================================
# ADMIN
# =============================================================================
@app.get("/api/admin/stats")
def admin_stats(db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as total FROM Search")
        total_searches = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) as total FROM User")
        total_users = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) as total FROM PetrolStation")
        total_stations = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) as total FROM User WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
        new_users = cur.fetchone()["total"]
        cur.execute("""
            SELECT query_text, COUNT(*) as count
            FROM Search WHERE query_text IS NOT NULL
            GROUP BY query_text ORDER BY count DESC LIMIT 10
        """)
        top_searches = cur.fetchall()
        cur.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM Search WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(timestamp) ORDER BY date
        """)
        searches_over_time = cur.fetchall()
    return {
        "total_searches": total_searches,
        "total_users": total_users,
        "total_stations": total_stations,
        "new_users_this_week": new_users,
        "top_searches": top_searches,
        "searches_over_time": searches_over_time,
    }

@app.get("/api/admin/search-logs")
def search_logs(page: int = 1, limit: int = 10, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    offset = (page - 1) * limit
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as total FROM Search")
        total = cur.fetchone()["total"]
        cur.execute("""
            SELECT s.*, u.name as user_name, u.email as user_email
            FROM Search s LEFT JOIN User u ON u.user_id = s.user_id
            ORDER BY s.timestamp DESC LIMIT %s OFFSET %s
        """, (limit, offset))
        logs = cur.fetchall()
    return {"total": total, "page": page, "limit": limit, "logs": logs}

@app.get("/api/admin/users")
def list_users(db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("SELECT user_id, name, email, preferred_theme, preferred_fuel, created_at FROM User ORDER BY created_at DESC")
        return cur.fetchall()

@app.put("/api/admin/users/{user_id}/role")
def update_user_role(user_id: int, db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    # Toggle: if user has a BusinessAdmin record, remove it; otherwise create one
    return {"message": "Role management handled via BusinessAdmin table"}

@app.get("/api/admin/export/search-logs")
def export_search_logs(db=Depends(get_db), current_user: dict = Depends(get_admin_user)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT s.search_id, u.name, u.email, s.query_text, s.results_count, s.timestamp
            FROM Search s LEFT JOIN User u ON u.user_id = s.user_id
            ORDER BY s.timestamp DESC
        """)
        logs = cur.fetchall()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["search_id", "name", "email", "query_text", "results_count", "timestamp"])
    writer.writeheader()
    writer.writerows(logs)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=search-logs.csv"}
    )

# =============================================================================
# REPORTS
# =============================================================================
@app.get("/api/reports/popular-stations")
def report_popular_stations(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ps.station_id, ps.name, ps.city, ps.country,
                   sa.view_count, sa.search_appearances,
                   COUNT(DISTINCT r.review_id) as review_count,
                   AVG(r.rating) as avg_rating,
                   (sa.search_appearances + sa.view_count) as popularity_score
            FROM PetrolStation ps
            LEFT JOIN StationAnalytics sa ON sa.station_id = ps.station_id
            LEFT JOIN Review r ON r.station_id = ps.station_id
            GROUP BY ps.station_id
            ORDER BY popularity_score DESC
        """)
        return cur.fetchall()

@app.get("/api/reports/price-trends")
def report_price_trends(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ps.name as station_name, ft.fuel_name, sft.price_per_liter, sft.last_updated
            FROM StationFuelType sft
            JOIN PetrolStation ps ON ps.station_id = sft.station_id
            JOIN FuelType ft ON ft.fuel_id = sft.fuel_type_id
            ORDER BY sft.last_updated DESC
        """)
        return cur.fetchall()

@app.get("/api/reports/user-activity")
def report_user_activity(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as new_users
            FROM User GROUP BY DATE(created_at) ORDER BY date
        """)
        registrations = cur.fetchall()
        cur.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as searches
            FROM Search GROUP BY DATE(timestamp) ORDER BY date
        """)
        searches = cur.fetchall()
    return {"registrations": registrations, "searches": searches}

@app.get("/api/reports/station-ratings")
def report_station_ratings(db=Depends(get_db)):
    with db.cursor() as cur:
        cur.execute("""
            SELECT ps.station_id, ps.name, ps.city, ps.country, ps.rating,
                   COUNT(r.review_id) as total_reviews,
                   AVG(r.rating) as calculated_avg
            FROM PetrolStation ps
            LEFT JOIN Review r ON r.station_id = ps.station_id
            GROUP BY ps.station_id
            ORDER BY calculated_avg DESC
        """)
        return cur.fetchall()
