import os
import sys
import django
import json
import base64
import requests
import time

# Add the project root to the python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'medid_backend.settings')
django.setup()

from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

# Configuration
API_BASE_URL = 'http://localhost:8000/api'
DEMO_ASSETS_DIR = os.path.join(os.path.dirname(__file__), 'demo_assets')

def create_demo_users():
    print("Creating demo healthcare providers...")
    demo_users = [
        {
            "username": "dr_alice",
            "email": "alice@medid.demo",
            "password": "demo_password_123",
            "first_name": "Dr. Alice",
            "last_name": "Smith"
        },
        {
            "username": "nurse_bob",
            "email": "bob@medid.demo",
            "password": "demo_password_123",
            "first_name": "Nurse Bob",
            "last_name": "Jones"
        },
        {
            "username": "demo_admin",
            "email": "admin@medid.demo",
            "password": "demo_password_123",
            "first_name": "System",
            "last_name": "Admin"
        }
    ]

    admin_token = None
    for u_data in demo_users:
        user, created = User.objects.get_or_create(
            username=u_data["username"],
            defaults={
                "email": u_data["email"],
                "first_name": u_data["first_name"],
                "last_name": u_data["last_name"]
            }
        )
        if created:
            user.set_password(u_data["password"])
            user.save()
            print(f"Created user {user.username}")
        else:
            print(f"User {user.username} already exists")

        token, _ = Token.objects.get_or_create(user=user)
        if user.username == "demo_admin":
            admin_token = token.key

    return admin_token

def get_base64_image(filename):
    filepath = os.path.join(DEMO_ASSETS_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Warning: Image {filepath} not found.")
        return None
    with open(filepath, "rb") as f:
        return base64.b64encode(f.read()).decode('utf-8')

def seed_patients(auth_token):
    headers = {
        'Authorization': f'Token {auth_token}',
        'Content-Type': 'application/json'
    }

    patients_data = [
        {
            "name": "Carlos Rodriguez",
            "date_of_birth": "1981-05-12",
            "gender": "M",
            "blood_group": "A+",
            "emergency_contact_name": "Maria Rodriguez (Wife)",
            "emergency_contact_phone": "+1-555-0100",
            "allergies": ["Penicillin", "Peanuts"],
            "current_medications": [{"name": "Lisinopril", "dosage": "10mg daily"}],
            "medical_conditions": [{"condition": "Hypertension", "status": "active"}],
            "emergency_summary": "Patient has hypertension. Severe peanut allergy - carries EpiPen.",
            "consent_status": "granted",
            "image_file": "patient1.jpg"
        },
        {
            "name": "Mei Lin",
            "date_of_birth": "1996-11-23",
            "gender": "F",
            "blood_group": "B-",
            "emergency_contact_name": "David Chen (Brother)",
            "emergency_contact_phone": "+1-555-0200",
            "allergies": [],
            "current_medications": [],
            "medical_conditions": [{"condition": "Asthma", "status": "active"}],
            "emergency_summary": "Exercise-induced asthma. Uses Albuterol inhaler as needed.",
            "consent_status": "granted",
            "image_file": "patient2.jpg"
        },
        {
            "name": "James Wilson",
            "date_of_birth": "1966-03-08",
            "gender": "M",
            "blood_group": "O+",
            "emergency_contact_name": "Sarah Wilson (Daughter)",
            "emergency_contact_phone": "+1-555-0300",
            "allergies": ["Latex"],
            "current_medications": [{"name": "Metformin", "dosage": "500mg twice daily"}, {"name": "Atorvastatin", "dosage": "20mg daily"}],
            "medical_conditions": [{"condition": "Type 2 Diabetes", "status": "active"}, {"condition": "Hyperlipidemia", "status": "active"}],
            "emergency_summary": "Type 2 diabetic on oral medication. Latex allergy.",
            "consent_status": "granted",
            "image_file": "patient3.jpg"
        }
    ]

    print(f"\nRegistering {len(patients_data)} synthetic patients via API...")
    for p_data in patients_data:
        print(f"\nProcessing {p_data['name']}...")
        image_file = p_data.pop("image_file")
        base64_img = get_base64_image(image_file)
        
        if not base64_img:
            print(f"Skipping {p_data['name']} due to missing image.")
            continue
            
        p_data["face_image_base64"] = base64_img

        try:
            response = requests.post(f"{API_BASE_URL}/patients/register", json=p_data, headers=headers)
            if response.status_code == 201:
                result = response.json()
                print(f"[SUCCESS] Successfully registered {p_data['name']} (ID: {result.get('id')})")
                print(f"   Biometric Quality: {result.get('biometric_quality_score', 'N/A')}")
            else:
                print(f"[ERROR] Failed to register {p_data['name']}. Status: {response.status_code}")
                print(f"   Response: {response.text}")
        except Exception as e:
            print(f"[ERROR] Error during registration: {str(e)}")

def main():
    print("========================================")
    print("MEDid Synthetic Demo Data Seeder")
    print("========================================")
    
    # Ensure services are up
    try:
        health = requests.get(f"{API_BASE_URL}/health", timeout=3)
        if health.status_code != 200:
            print(f"Warning: Health check returned {health.status_code}")
    except Exception:
        print(f"ERROR: Cannot reach backend API at {API_BASE_URL}. Ensure Django server is running.")
        sys.exit(1)
        
    admin_token = create_demo_users()
    if admin_token:
        seed_patients(admin_token)
    else:
        print("Failed to get admin token.")
        
    print("\n✅ Demo data seeding complete!")

if __name__ == '__main__':
    main()
