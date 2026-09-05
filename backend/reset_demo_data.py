import os
import sys
import django

# Add the project root to the python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'medid_backend.settings')
django.setup()

from django.contrib.auth.models import User
from api.models import Patient, BiometricTemplate, AuditLog

def reset_demo_data():
    print("========================================")
    print("MEDid Demo Data Reset")
    print("========================================")
    
    demo_usernames = ["dr_alice", "nurse_bob", "demo_admin"]
    demo_patient_names = ["Carlos Rodriguez", "Mei Lin", "James Wilson"]

    print("Deleting demo patients and their biometric templates...")
    patients_deleted, _ = Patient.objects.filter(name__in=demo_patient_names).delete()
    print(f"[SUCCESS] Deleted {patients_deleted} demo patients (cascaded to templates/access logs).")

    print("Deleting demo healthcare providers...")
    users_deleted, _ = User.objects.filter(username__in=demo_usernames).delete()
    print(f"[SUCCESS] Deleted {users_deleted} demo users.")
    
    print("Cleaning up associated audit logs...")
    # This will delete any audit logs where the username matches our demo users
    # or the patient matches our demo patients, just in case they weren't cascaded.
    logs_deleted, _ = AuditLog.objects.filter(user_id__in=demo_usernames).delete()
    print(f"[SUCCESS] Deleted {logs_deleted} audit logs created by demo users.")

    print("\n[SUCCESS] Demo data reset complete!")

if __name__ == '__main__':
    reset_demo_data()
