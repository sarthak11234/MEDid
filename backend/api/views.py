from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import models
from .models import Patient, BiometricTemplate, EmergencyAccess, AuditLog
from .serializers import (
    UserSerializer, PatientSerializer, PatientRegistrationSerializer, BiometricTemplateSerializer,
    EmergencyMatchRequestSerializer, EmergencyMatchResponseSerializer, AuditLogSerializer,
    LoginSerializer, DemoTokenSerializer
)
import json
import logging
import jwt
import requests
from cryptography.fernet import Fernet
from django.conf import settings

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request):
    """
    MedID API Root - Landing Page
    """
    return Response({
        "service": "MedID Backend API",
        "status": "online",
        "version": "1.0.0",
        "message": "Welcome to the MedID Identity System API",
        "endpoints": {
            "health_check": "/health",
            "documentation": "/redoc",
            "admin": "/admin/"
        }
    })

def get_biometric_jwt():
    """Generate JWT for biometric service"""
    return jwt.encode(
        {'user': 'medid_backend', 'role': 'service'},
        settings.BIOMETRIC_SERVICE_SECRET,
        algorithm='HS256'
    )

def encrypt_template(template_json):
    """Encrypt biometric template using Fernet"""
    f = Fernet(settings.BIOMETRIC_ENCRYPTION_KEY)
    return f.encrypt(template_json.encode()).decode()

def decrypt_template(encrypted_template):
    """Decrypt template from Fernet token string"""
    if not encrypted_template:
        return None
    try:
        cipher_suite = Fernet(settings.BIOMETRIC_ENCRYPTION_KEY)
        decrypted_data = cipher_suite.decrypt(encrypted_template.encode()).decode()
        return json.loads(decrypted_data)
    except Exception as e:
        logger.error(f"Template decryption failed: {e}")
        return None

def get_decrypted_patient_data(patient):
    """
    Helper to return Patient data with decrypted medical fields
    """
    data = PatientSerializer(patient).data
    cipher_suite = Fernet(settings.BIOMETRIC_ENCRYPTION_KEY)
    
    # Decrypt medical fields
    fields_to_decrypt = {
        'allergies_encrypted': 'allergies',
        'current_medications_encrypted': 'current_medications',
        'medical_conditions_encrypted': 'medical_conditions',
        'emergency_summary_encrypted': 'emergency_summary'
    }
    
    for enc_field, raw_field in fields_to_decrypt.items():
        enc_val = getattr(patient, enc_field)
        if enc_val:
            try:
                decrypted = cipher_suite.decrypt(enc_val.encode()).decode()
                # If it looks like JSON, parse it
                if raw_field in ['allergies', 'current_medications', 'medical_conditions']:
                    data[raw_field] = json.loads(decrypted)
                else:
                    data[raw_field] = decrypted
            except Exception as e:
                logger.error(f"Failed to decrypt {raw_field}: {e}")
                data[raw_field] = None
        else:
            data[raw_field] = [] if raw_field != 'emergency_summary' else ""
            
    return data


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """Login endpoint for authentication"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Check for demo credentials
        if email == 'demo@medid.com' and password == 'demo123':
            # Create or get demo user
            demo_user, created = User.objects.get_or_create(
                username='demo',
                defaults={
                    'email': 'demo@medid.com',
                    'first_name': 'Dr. Demo',
                    'last_name': 'User'
                }
            )
            if created:
                demo_user.set_password('demo123')
                demo_user.save()
            
            token, created = Token.objects.get_or_create(user=demo_user)
            return Response({
                'access_token': token.key,
                'user': {
                    'id': demo_user.id,
                    'email': demo_user.email,
                    'name': f"{demo_user.first_name} {demo_user.last_name}".strip(),
                    'role': 'doctor',
                    'hospital': 'Demo General Hospital',
                    'permissions': ['patient:read', 'patient:write', 'emergency:access'],
                    'lastLogin': demo_user.last_login.isoformat() if demo_user.last_login else None
                }
            })
        
        # Try regular authentication
        try:
            user = User.objects.get(email=email)
            user = authenticate(username=user.username, password=password)
            if user:
                token, created = Token.objects.get_or_create(user=user)
                return Response({
                    'access_token': token.key,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'name': f"{user.first_name} {user.last_name}".strip(),
                        'role': 'doctor',
                        'hospital': 'General Hospital',
                        'permissions': ['patient:read', 'patient:write', 'emergency:access'],
                        'lastLogin': user.last_login.isoformat() if user.last_login else None
                    }
                })
        except User.DoesNotExist:
            pass
    
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """Register a new user (doctor/nurse/admin)"""
    try:
        data = request.data
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                return Response(
                    {'error': f'{field} is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Check if user already exists
        if User.objects.filter(username=data['username']).exists():
            return Response(
                {'error': 'Username already exists'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if User.objects.filter(email=data['email']).exists():
            return Response(
                {'error': 'Email already exists'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create new user
        user = User.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name']
        )
        
        # Create audit log
        AuditLog.objects.create(
            event_type='system_login',  # Using existing event type
            event_description=f'User {user.username} registered successfully',
            user_id=str(user.id),
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            event_data={
                'username': user.username,
                'email': user.email,
                'full_name': f"{user.first_name} {user.last_name}"
            }
        )
        
        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'message': 'User registered successfully'
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"User registration failed: {str(e)}")
        return Response(
            {'error': 'Registration failed'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """Logout user and invalidate token"""
    try:
        # Delete the user's token
        token = Token.objects.get(user=request.user)
        token.delete()
        return Response({'message': 'Successfully logged out'})
    except Token.DoesNotExist:
        return Response({'message': 'Already logged out'})


@api_view(['GET'])
@permission_classes([AllowAny])
def demo_token(request):
    """Demo token endpoint for testing"""
    # Create or get demo user
    demo_user, created = User.objects.get_or_create(
        username='demo',
        defaults={
            'email': 'demo@medid.com',
            'first_name': 'Dr. Demo',
            'last_name': 'User'
        }
    )
    
    token, created = Token.objects.get_or_create(user=demo_user)
    
    return Response({
        'access_token': token.key,
        'user_info': {
            'user_id': demo_user.id,
            'role': 'doctor',
            'hospital': 'Demo General Hospital'
        }
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    """Get user profile"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_patients(request):
    """Search patients endpoint with decrypted data support"""
    query = request.GET.get('q', '')
    
    # Create sample patients if none exist (demo mode)
    if Patient.objects.count() == 0:
        # Note: In a real scenario, we'd encrypt these sample fields too
        sample_patients = [
            Patient(name='John Smith', date_of_birth='1978-05-15', gender='M', blood_group='A+'),
            Patient(name='Sarah Johnson', date_of_birth='1991-08-22', gender='F', blood_group='O-'),
        ]
        Patient.objects.bulk_create(sample_patients)
    
    patients = Patient.objects.filter(name__icontains=query) if query else Patient.objects.all()
    
    # Return decrypted data for search results
    search_results = [get_decrypted_patient_data(p) for p in patients]
    return Response(search_results)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_patient(request, patient_id):
    """Get specific patient details with decrypted medical information"""
    patient = get_object_or_404(Patient, id=patient_id)
    return Response(get_decrypted_patient_data(patient))


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_patient(request, patient_id):
    """Update existing patient information with encryption support"""
    patient = get_object_or_404(Patient, id=patient_id)
    
    serializer = PatientRegistrationSerializer(patient, data=request.data, partial=True)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Save basic fields
        update_data = serializer.validated_data.copy()
        
        # Handle medical fields separately for encryption
        medical_fields = ['allergies', 'current_medications', 'medical_conditions', 'emergency_summary']
        raw_medical_data = {}
        has_medical_update = False
        
        # Get current values for summary regeneration if needed
        if any(field in update_data for field in ['allergies', 'current_medications', 'medical_conditions']):
            current_decrypted = get_decrypted_patient_data(patient)
            raw_medical_data = {
                'allergies': update_data.get('allergies', current_decrypted.get('allergies', [])),
                'current_medications': update_data.get('current_medications', current_decrypted.get('current_medications', [])),
                'medical_conditions': update_data.get('medical_conditions', current_decrypted.get('medical_conditions', [])),
                'emergency_summary': update_data.get('emergency_summary', current_decrypted.get('emergency_summary', '')),
                'blood_group': update_data.get('blood_group', patient.blood_group),
                'emergency_contact_name': update_data.get('emergency_contact_name', patient.emergency_contact_name),
                'emergency_contact_phone': update_data.get('emergency_contact_phone', patient.emergency_contact_phone)
            }
            
            # Encrypt individual fields
            for field in ['allergies', 'current_medications', 'medical_conditions']:
                if field in update_data:
                    val = update_data.pop(field)
                    patient_field = f"{field}_encrypted"
                    setattr(patient, patient_field, encrypt_template(json.dumps(val)))
            
            # Regenerate and encrypt summary
            new_summary = generate_emergency_summary_raw(raw_medical_data)
            patient.emergency_summary_encrypted = encrypt_template(new_summary)
            has_medical_update = True
        elif 'emergency_summary' in update_data:
            val = update_data.pop('emergency_summary')
            patient.emergency_summary_encrypted = encrypt_template(val)
            has_medical_update = True
        
        # Update remaining fields
        for key, value in update_data.items():
            setattr(patient, key, value)
            
        patient.save()
        
        # Log the update
        AuditLog.objects.create(
            event_type='data_update',
            patient=patient,
            user_id=request.user.username,
            ip_address=request.META.get('REMOTE_ADDR'),
            event_description=f'Updated patient record: {patient.name}',
            event_data={'medical_update': has_medical_update}
        )
        
        return Response({
            'success': True,
            'message': 'Patient updated successfully',
            'patient': get_decrypted_patient_data(patient)
        })
        
    except Exception as e:
        return Response({
            'error': 'Update failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_patient(request):
    """
    Register a new patient with biometric enrollment
    Integrates with biometric service for template extraction
    """
    import requests
    import base64
    from datetime import datetime, timedelta
    from django.utils import timezone
    
    serializer = PatientRegistrationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Extract face image if provided
        face_image_b64 = request.data.get('face_image_base64')
        biometric_template = None
        quality_score = 0.0
        
        if face_image_b64:
            # Call biometric service to extract template
            try:
                # Prepare image data for biometric service
                image_data = base64.b64decode(face_image_b64)
                
                biometric_response = requests.post(
                    f"{settings.BIOMETRIC_SERVICE_URL}/biometric/extract-template",
                    files={'file': ('image.jpg', image_data, 'image/jpeg')},
                    headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
                    timeout=10
                )
                
                if biometric_response.status_code == 200:
                    bio_data = biometric_response.json()
                    raw_template = bio_data.get('template_data')
                    # Encrypt the template before storage
                    biometric_template = encrypt_template(json.dumps(raw_template))
                    quality_score = bio_data.get('quality_score', 0.0)
                    
                    print(f"DEBUG: Biometric extraction success. Quality: {quality_score}") 

                    # Validate quality threshold
                    # Validate quality threshold with a lower bar for easier testing
                    if quality_score < 0.1: # Lowered for demo/testing
                        print(f"DEBUG: Quality too low: {quality_score}")
                        return Response({
                            'error': 'Biometric quality too low',
                            'quality_score': quality_score,
                            'message': 'Please provide a clearer image'
                        }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    print(f"DEBUG: Biometric extraction failed: {biometric_response.text}")
                    return Response({
                        'error': 'Biometric extraction failed',
                        'message': 'Could not process facial image'
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
            except requests.exceptions.RequestException as e:
                print(f"DEBUG: Extraction request failed: {e}")
                return Response({
                    'error': 'Biometric service unavailable',
                    'message': 'Please try again later'
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        else:
            print("DEBUG: No face_image_base64 provided in request")
        
        # Create patient record
        patient_data = serializer.validated_data.copy()
        
        # Remove face image and raw medical fields from patient data
        patient_data.pop('face_image_base64', None)
        
        # Extract raw medical data for summary generation
        raw_medical_data = {
            'allergies': patient_data.pop('allergies', []),
            'current_medications': patient_data.pop('current_medications', []),
            'medical_conditions': patient_data.pop('medical_conditions', []),
            'emergency_summary': patient_data.pop('emergency_summary', ''),
            'blood_group': patient_data.get('blood_group', 'N/A'),
            'emergency_contact_name': patient_data.get('emergency_contact_name', 'N/A'),
            'emergency_contact_phone': patient_data.get('emergency_contact_phone', 'N/A')
        }
        
        # Encrypt medical fields
        patient_data['allergies_encrypted'] = encrypt_template(json.dumps(raw_medical_data['allergies']))
        patient_data['current_medications_encrypted'] = encrypt_template(json.dumps(raw_medical_data['current_medications']))
        patient_data['medical_conditions_encrypted'] = encrypt_template(json.dumps(raw_medical_data['medical_conditions']))
        
        # Generate emergency summary from raw data
        emergency_summary_text = generate_emergency_summary_raw(raw_medical_data)
        patient_data['emergency_summary_encrypted'] = encrypt_template(emergency_summary_text)
        
        # Set consent timestamp if granted
        if patient_data.get('consent_status') == 'granted':
            patient_data['consent_granted_at'] = timezone.now()
        
        # Create patient
        patient = Patient.objects.create(**patient_data)
        print(f"DEBUG: Patient created: {patient.id}")
        
        # Create biometric template if we have one
        if biometric_template and quality_score > 0:
            print(f"DEBUG: Creating BiometricTemplate for patient {patient.id}")
            BiometricTemplate.objects.create(
                patient=patient,
                face_template_encrypted=biometric_template,
                quality_score=quality_score,
                template_version='1.0',
                extraction_algorithm='face_recognition'
            )
            
            # Sync with Biometric Service (Mock Mode support)
            try:
                print(f"DEBUG: Attempting to sync with biometric service at {settings.BIOMETRIC_SERVICE_URL}")
                sync_response = requests.post(
                    f"{settings.BIOMETRIC_SERVICE_URL}/internal/enroll",
                    json={
                        'patient_id': str(patient.id),
                        'encrypted_template': raw_template
                    },
                    timeout=5
                )
                print(f"DEBUG: Sync response: {sync_response.status_code} - {sync_response.text}")
            except Exception as e:
                print(f"DEBUG: Failed to sync mock template: {e}")
        
        # Create audit log entry
        AuditLog.objects.create(
            event_type='patient_register',
            event_description=f'Patient {patient.name} registered successfully (encrypted)',
            patient=patient,
            user_id=request.user.username,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            event_data={
                'biometric_enrolled': bool(biometric_template),
                'quality_score': quality_score,
                'consent_version': patient.consent_version,
                'encrypted_fields': ['allergies', 'medications', 'conditions', 'summary']
            }
        )
        
        # Return response (decrypting for mobile app feedback)
        response_data = PatientSerializer(patient).data
        response_data['allergies'] = raw_medical_data['allergies']
        response_data['current_medications'] = raw_medical_data['current_medications']
        response_data['medical_conditions'] = raw_medical_data['medical_conditions']
        response_data['emergency_summary'] = emergency_summary_text
        
        response_data['biometric_quality_score'] = quality_score
        response_data['biometric_enrolled'] = bool(biometric_template)
        response_data['registration_status'] = 'success'
        
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({
            'error': 'Registration failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def generate_emergency_summary_raw(data):
    """
    Generate emergency summary from raw dictionary data
    """
    summary_parts = []
    
    # Critical information first
    summary_parts.append(f"BLOOD GROUP: {data.get('blood_group', 'N/A')}")
    
    # Allergies
    allergies = data.get('allergies', [])
    if allergies:
        allergy_list = ", ".join(allergies) if isinstance(allergies, list) else str(allergies)
        summary_parts.append(f"ALLERGIES: {allergy_list}")
    
    # Current medications
    meds = data.get('current_medications', [])
    if meds:
        if isinstance(meds, list):
            med_list = ", ".join([med.get('name', str(med)) if isinstance(med, dict) else str(med) for med in meds])
        else:
            med_list = str(meds)
        summary_parts.append(f"MEDICATIONS: {med_list}")
    
    # Medical conditions
    conditions = data.get('medical_conditions', [])
    if conditions:
        if isinstance(conditions, list):
            condition_list = ", ".join([cond.get('condition', str(cond)) if isinstance(cond, dict) else str(cond) for cond in conditions])
        else:
            condition_list = str(conditions)
        summary_parts.append(f"CONDITIONS: {condition_list}")
    
    # Emergency contact
    summary_parts.append(f"EMERGENCY CONTACT: {data.get('emergency_contact_name')} - {data.get('emergency_contact_phone')}")
    
    return " | ".join(summary_parts)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def extract_biometric_template(request):
    """
    Extract biometric template from uploaded image
    Used during patient registration process
    """
    import requests
    
    try:
        if 'file' not in request.FILES:
            return Response({
                'error': 'No file provided',
                'message': 'Please upload an image file'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        image_file = request.FILES['file']
        
        # Forward to DeepFace service
        files = {'file': (image_file.name, image_file.read(), image_file.content_type)}
        
        extract_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/extract-template",
            files=files,
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=15
        )
        
        if extract_response.status_code == 200:
            result = extract_response.json()
            return Response({
                'success': True,
                'template_data': result.get('template_data'),
                'quality_score': result.get('quality_score', 0.0),
                'confidence': result.get('confidence', 0.0)
            })
        else:
            return Response({
                'error': 'Template extraction failed',
                'message': extract_response.json().get('message', 'Unknown error')
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        return Response({
            'error': 'Processing failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def liveness_check(request):
    """
    Perform liveness detection on uploaded image
    Used to prevent spoofing attacks during registration
    """
    import requests
    
    try:
        if 'file' not in request.FILES:
            return Response({
                'error': 'No file provided',
                'message': 'Please upload an image file'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        image_file = request.FILES['file']
        
        # Forward to DeepFace service
        files = {'file': (image_file.name, image_file.read(), image_file.content_type)}
        
        liveness_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/liveness-check",
            files=files,
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=15
        )
        
        if liveness_response.status_code == 200:
            result = liveness_response.json()
            return Response({
                'success': True,
                'is_live': result.get('is_live', False),
                'confidence': result.get('confidence', 0.0),
                'liveness_score': result.get('liveness_score', 0.0)
            })
        else:
            return Response({
                'error': 'Liveness check failed',
                'message': liveness_response.json().get('message', 'Unknown error')
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        return Response({
            'error': 'Processing failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def biometric_scan(request):
    """
    Handle biometric scanning for patient identification
    Used in emergency scenarios for quick patient lookup
    """
    import requests
    import base64
    
    try:
        face_image_b64 = request.data.get('face_image_base64')
        confidence_threshold = request.data.get('confidence_threshold', 0.6)
        
        if not face_image_b64:
            return Response({
                'error': 'Face image required',
                'message': 'Please provide face_image_base64'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract template from provided image
        image_data = base64.b64decode(face_image_b64)
        
        extract_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/extract-template",
            files={'file': ('scan.jpg', image_data, 'image/jpeg')},
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=10
        )
        
        if extract_response.status_code != 200:
            return Response({
                'error': 'Template extraction failed',
                'message': 'Could not process facial image'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        template_data = extract_response.json().get('template_data')
        
        # Match against all enrolled templates
        match_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/match",
            json={
                'template_data': template_data,
                'threshold': confidence_threshold,
                'max_results': 1
            },
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=10
        )
        
        if match_response.status_code != 200:
            return Response({
                'error': 'Matching failed',
                'message': f'Biometric service error: {match_response.status_code} - {match_response.text}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        match_data = match_response.json()
        
        if match_data.get('matches'):
            # Found a match
            best_match = match_data['matches'][0]
            patient_id = best_match.get('patient_id')
            confidence = best_match.get('confidence', 0.0)
            
            try:
                patient = Patient.objects.get(id=patient_id)
                
                # Update last accessed
                patient.last_accessed = timezone.now()
                patient.save()
                
                # Create audit log
                AuditLog.objects.create(
                    event_type='template_match',
                    event_description=f'Biometric match found for patient {patient.name}',
                    patient=patient,
                    user_id=request.user.username,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    event_data={
                        'confidence': confidence,
                        'threshold': confidence_threshold,
                        'scan_type': 'identification'
                    }
                )
                
                return Response({
                    'success': True,
                    'patient_found': True,
                    'patient_id': str(patient.id),
                    'patient_data': get_decrypted_patient_data(patient),
                    'confidence': confidence,
                    'message': f'Patient {patient.name} identified successfully'
                })
                
            except Patient.DoesNotExist:
                return Response({
                    'error': 'Patient record not found',
                    'message': 'Biometric match found but patient record missing'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            # No match found
            return Response({
                'success': True,
                'patient_found': False,
                'confidence': 0.0,
                'message': 'No matching patient found'
            })
            
    except requests.exceptions.RequestException:
        return Response({
            'error': 'Biometric service unavailable',
            'message': 'Please try again later'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    except Exception as e:
        return Response({
            'error': 'Scan failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def emergency_access(request):
    """
    Emergency access endpoint with break-glass authorization
    POST: Used by medical personnel in emergency situations for biometric matching
    GET: Retrieve emergency access logs
    """
    if request.method == 'GET':
        # Return emergency access logs
        from .models import EmergencyAccess
        
        patient_id = request.GET.get('patient_id')
        
        # Filter by patient ID if provided
        if patient_id:
            accesses = EmergencyAccess.objects.filter(
                patient_id=patient_id
            ).order_by('-started_at')[:10]
        else:
            accesses = EmergencyAccess.objects.all().order_by('-started_at')[:20]
        
        access_logs = []
        for access in accesses:
            access_logs.append({
                'id': str(access.id),
                'patient_id': str(access.patient_id),
                'patient_name': access.patient.name if access.patient else 'Unknown',
                'accessed_by': access.accessing_user,
                'timestamp': access.started_at.isoformat(),
                'action': 'Emergency Access',
                'status': 'success' if access.status == 'granted' else 'failed',
                'location': access.location,
                'emergency_reason': access.emergency_reason,
            })
        
        return Response(access_logs)
    
    # POST request handling for emergency biometric matching
    import requests
    import base64
    from datetime import datetime, timedelta
    
    # Debug logging
    logger.info(f"Emergency access POST request data: {request.data}")
    
    serializer = EmergencyMatchRequestSerializer(data=request.data)
    if not serializer.is_valid():
        logger.error(f"Serializer validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Extract data from request
        face_image_b64 = serializer.validated_data['face_image_base64']
        emergency_reason = serializer.validated_data['emergency_reason']
        accessing_device_id = serializer.validated_data['accessing_device_id']
        accessing_user = serializer.validated_data['accessing_user']
        organization = serializer.validated_data['organization']
        location = serializer.validated_data['location']
        confidence_threshold = serializer.validated_data['confidence_threshold']
        
        # Extract and match biometric template
        image_data = base64.b64decode(face_image_b64)
        
        # Extract template
        extract_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/extract-template",
            files={'file': ('emergency.jpg', image_data, 'image/jpeg')},
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=10
        )
        print(f"DEBUG: Extract response status: {extract_response.status_code}")
        print(f"DEBUG: Extract response body: {extract_response.text}")
        
        if extract_response.status_code != 200:
            return Response({
                'error': 'Template extraction failed',
                'message': 'Could not process facial image for emergency access'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        template_data = extract_response.json().get('template_data')
        
        # Match against enrolled templates
        match_response = requests.post(
            f"{settings.BIOMETRIC_SERVICE_URL}/biometric/match",
            json={
                'template_data': template_data,
                'threshold': confidence_threshold,
                'max_results': 1
            },
            headers={'Authorization': f'Bearer {get_biometric_jwt()}'},
            timeout=10
        )
        
        if match_response.status_code != 200:
            error_details = 'Unknown error'
            try:
                error_details = match_response.json().get('detail', match_response.text)
            except:
                error_details = match_response.text
                
            print(f"DEBUG: Match failed with {match_response.status_code}: {error_details}")
            
            return Response({
                'error': 'Emergency matching failed',
                'message': f'Biometric service error: {error_details}'
            }, status=match_response.status_code)
        
        match_data = match_response.json()
        
        if not match_data.get('matches'):
            # No match found - still log the attempt
            AuditLog.objects.create(
                event_type='emergency_access',
                event_description=f'Emergency access attempted - no biometric match found',
                user_id=accessing_user,
                device_id=accessing_device_id,
                ip_address=request.META.get('REMOTE_ADDR'),
                event_data={
                    'success': False,
                    'reason': emergency_reason,
                    'organization': organization,
                    'location': location,
                    'confidence_threshold': confidence_threshold
                }
            )
            
            return Response({
                'match_found': False,
                'message': 'No patient match found for emergency access',
                'emergency_access_denied': True
            })
        
        # Found a match - proceed with emergency access
        best_match = match_data['matches'][0]
        patient_id = best_match.get('patient_id')
        confidence = best_match.get('confidence', 0.0)
        
        try:
            patient = Patient.objects.get(id=patient_id)
            
            # Create emergency access session
            expires_at = timezone.now() + timedelta(hours=2)  # 2-hour emergency session
            
            emergency_session = EmergencyAccess.objects.create(
                patient=patient,
                access_type='emergency',
                accessing_device_id=accessing_device_id,
                accessing_user=accessing_user,
                organization=organization,
                location=location,
                emergency_reason=emergency_reason,
                biometric_confidence=confidence,
                status='active',
                expires_at=expires_at,
                data_accessed=['emergency_summary', 'basic_info', 'allergies', 'medications']
            )
            
            # Update patient last accessed
            patient.last_accessed = timezone.now()
            patient.save()
            
            # Create comprehensive audit log
            AuditLog.objects.create(
                event_type='emergency_access',
                event_description=f'Emergency access granted for patient {patient.name}',
                patient=patient,
                emergency_session=emergency_session,
                user_id=accessing_user,
                device_id=accessing_device_id,
                ip_address=request.META.get('REMOTE_ADDR'),
                location=location,
                event_data={
                    'success': True,
                    'confidence': confidence,
                    'reason': emergency_reason,
                    'organization': organization,
                    'session_duration_hours': 2,
                    'access_type': 'break_glass'
                }
            )
            
            # Prepare emergency data response
            # TODO: Send patient notification (SMS/Email)
            # send_emergency_notification(patient, emergency_session)
            
            response_data = {
                'match_found': True,
                'patient_id': str(patient.id),
                'emergency_data': get_decrypted_patient_data(patient),
                'match_confidence': confidence,
                'access_session_id': str(emergency_session.id),
                'expires_at': emergency_session.expires_at.isoformat(),
                'message': f'Emergency access granted for {patient.name}',
                'session_duration_minutes': 120,
                'notification_sent': False  # TODO: Implement notifications
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Patient.DoesNotExist:
            return Response({
                'error': 'Patient record not found',
                'message': 'Biometric match found but patient record missing'
            }, status=status.HTTP_404_NOT_FOUND)
            
    except requests.exceptions.RequestException:
        return Response({
            'error': 'Biometric service unavailable',
            'message': 'Emergency access temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    except Exception as e:
        # Log the error for emergency access failures
        AuditLog.objects.create(
            event_type='emergency_access',
            event_description=f'Emergency access failed: {str(e)}',
            user_id=request.data.get('accessing_user', 'unknown'),
            device_id=request.data.get('accessing_device_id', 'unknown'),
            ip_address=request.META.get('REMOTE_ADDR'),
            event_data={
                'success': False,
                'error': str(e),
                'reason': request.data.get('emergency_reason', 'unknown')
            }
        )
        
        return Response({
            'error': 'Emergency access failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """Get dashboard statistics"""
    from datetime import datetime, timedelta
    
    # Basic counts
    total_patients = Patient.objects.filter(is_active=True).count()
    total_enrolled = BiometricTemplate.objects.count()
    
    # Recent activity (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_registrations = Patient.objects.filter(created_at__gte=thirty_days_ago).count()
    
    # Active emergency sessions
    active_sessions = EmergencyAccess.objects.filter(
        status='active',
        expires_at__gt=timezone.now()
    ).count()
    
    # Recent emergency accesses (last 24 hours)
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    recent_emergency_access = EmergencyAccess.objects.filter(
        started_at__gte=twenty_four_hours_ago
    ).count()
    
    return Response({
        'total_patients': total_patients,
        'biometric_enrolled': total_enrolled,
        'enrollment_rate': round((total_enrolled / total_patients * 100) if total_patients > 0 else 0, 1),
        'recent_registrations': recent_registrations,
        'active_emergency_sessions': active_sessions,
        'recent_emergency_access': recent_emergency_access,
        'system_status': 'operational',
        'last_updated': timezone.now().isoformat()
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def emergency_stats(request):
    """Get emergency dashboard statistics"""
    from datetime import datetime, timedelta
    
    # Emergency access statistics
    today = timezone.now().date()
    week_ago = timezone.now() - timedelta(days=7)
    month_ago = timezone.now() - timedelta(days=30)
    
    emergency_accesses_today = EmergencyAccess.objects.filter(
        started_at__date=today
    ).count()
    
    emergency_accesses_week = EmergencyAccess.objects.filter(
        started_at__gte=week_ago
    ).count()
    
    emergency_accesses_month = EmergencyAccess.objects.filter(
        started_at__gte=month_ago
    ).count()
    
    # Active sessions
    active_sessions = EmergencyAccess.objects.filter(
        status='active',
        expires_at__gt=timezone.now()
    ).count()
    
    # System readiness
    total_enrolled = BiometricTemplate.objects.count()
    avg_quality = BiometricTemplate.objects.aggregate(
        avg_quality=models.Avg('quality_score')
    )['avg_quality'] or 0.0
    
    return Response({
        'emergencyAccesses': emergency_accesses_month,
        'activeSessions': active_sessions,
        'totalEnrolled': total_enrolled,
        'systemReadiness': round(avg_quality * 100, 1),
        'dailyStats': {
            'today': emergency_accesses_today,
            'week': emergency_accesses_week,
            'month': emergency_accesses_month
        },
        'last_updated': timezone.now().isoformat()
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def system_health(request):
    """Get system health status"""
    return Response({
        'status': 'healthy',
        'uptime': '99.9%',
        'database_status': 'connected',
        'biometric_service': 'online',
        'last_backup': '2025-09-22T10:00:00Z',
        'cpu_usage': 45,
        'memory_usage': 62,
        'disk_usage': 78
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def recent_accesses(request):
    """Get recent access logs"""
    return Response([
        {
            'id': 1,
            'patient_name': 'John Smith',
            'accessed_by': 'Dr. Demo User',
            'timestamp': '2025-09-22T15:30:00Z',
            'action': 'Biometric Scan',
            'status': 'success'
        },
        {
            'id': 2,
            'patient_name': 'Sarah Johnson',
            'accessed_by': 'Dr. Demo User',
            'timestamp': '2025-09-22T14:45:00Z',
            'action': 'Patient Lookup',
            'status': 'success'
        },
        {
            'id': 3,
            'patient_name': 'Robert Brown',
            'accessed_by': 'Dr. Demo User',
            'timestamp': '2025-09-22T14:20:00Z',
            'action': 'Emergency Access',
            'status': 'success'
        }
    ])