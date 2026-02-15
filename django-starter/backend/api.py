from ninja import NinjaAPI, Schema
from ninja.security import HttpBearer
from datetime import datetime, timezone
from django.conf import settings
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from core.models import ToDo

api = NinjaAPI()

# ============== SCHEMAS ==============

class ToDoSchema(Schema):
    title: str = ""
    description: str = ""
    completed: bool = False


class TokenObtainPairSchema(Schema):
    email: str
    password: str


class TokenRefreshSchema(Schema):
    refresh: str = None


class TokenVerifySchema(Schema):
    token: str = None


class TokenResponseSchema(Schema):
    access: str
    refresh: str
    access_expiry: int
    refresh_expiry: int
    access_expires_in: int
    refresh_expires_in: int


class RefreshResponseSchema(Schema):
    access: str
    access_expiry: int
    access_expires_in: int


# ============== AUTHENTICATION (FIXED WITH DEBUGGING) ==============

from typing import Optional, Any

class CustomJWTAuth:
    """
    Custom JWT Auth that works with both Bearer tokens and cookies
    """
    def __call__(self, request):
        return self.authenticate(request)
    
    def authenticate(self, request) -> Optional[Any]:
        # DEBUG: Print all headers
        print("=" * 50)
        print("AUTHENTICATION DEBUG")
        print("=" * 50)
        print(f"All headers: {dict(request.headers)}")
        
        # Try Authorization header first
        auth_header = request.headers.get('Authorization', '')
        print(f"Authorization header: '{auth_header}'")
        
        token = None
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            print(f"Extracted Bearer token: {token[:20]}..." if token else "No token")
        
        # Fallback to cookie
        if not token:
            token = request.COOKIES.get('access')
            print(f"Cookie token: {token[:20]}..." if token else "No cookie token")
        
        if not token:
            print("❌ No token found in header or cookie")
            return None
        
        try:
            # Validate the token
            print(f"Validating token...")
            access_token = AccessToken(token)
            print(f"Token payload: {dict(access_token.payload)}")
            
            user_id = access_token.get('user_id')
            print(f"User ID from token: {user_id}")
            
            if not user_id:
                print("❌ No user_id in token")
                return None
            
            # Get user from database
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)
            print(f"✅ User found: {user.email} (ID: {user.id})")
            print(f"User is_active: {user.is_active}")
            print("=" * 50)
            return user
            
        except TokenError as e:
            print(f"❌ TokenError: {e}")
            return None
        except InvalidToken as e:
            print(f"❌ InvalidToken: {e}")
            return None
        except User.DoesNotExist:
            print(f"❌ User with ID {user_id} does not exist")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return None


# ============== HELPER FUNCTIONS ==============

def add_token_cookies(response: HttpResponse, access_token: str, refresh_token: str = None):
    """Helper to add JWT tokens to cookies"""
    response.set_cookie(
        'access',
        access_token,
        max_age=settings.AUTH_COOKIE_ACCESS_MAX_AGE,
        path=settings.AUTH_COOKIE_PATH,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=settings.AUTH_COOKIE_HTTP_ONLY,
        samesite=settings.AUTH_COOKIE_SAMESITE
    )
    
    if refresh_token:
        response.set_cookie(
            'refresh',
            refresh_token,
            max_age=settings.AUTH_COOKIE_REFRESH_MAX_AGE,
            path=settings.AUTH_COOKIE_PATH,
            secure=settings.AUTH_COOKIE_SECURE,
            httponly=settings.AUTH_COOKIE_HTTP_ONLY,
            samesite=settings.AUTH_COOKIE_SAMESITE
        )


def get_token_expiry_info(access_token: str, refresh_token: str = None):
    """Extract expiry information from tokens"""
    try:
        access_token_obj = AccessToken(access_token)
        access_exp = access_token_obj['exp']
        
        now = datetime.now(timezone.utc).timestamp()
        
        result = {
            'access_expiry': access_exp,
            'access_expires_in': int(access_exp - now)
        }
        
        if refresh_token:
            refresh_token_obj = RefreshToken(refresh_token)
            refresh_exp = refresh_token_obj['exp']
            result['refresh_expiry'] = refresh_exp
            result['refresh_expires_in'] = int(refresh_exp - now)
        
        return result
    except Exception:
        return {}


# ============== JWT ENDPOINTS ==============

@api.post("/jwt/create/", response=TokenResponseSchema, tags=["Authentication"])
def token_obtain_pair(request, data: TokenObtainPairSchema):
    """
    Login endpoint - Creates access and refresh tokens
    """
    from django.contrib.auth import authenticate
    
    # Try to authenticate with email (assuming email backend is configured)
    user = authenticate(request, email=data.email, password=data.password)
    
    # If that didn't work, try with username=email
    if user is None:
        user = authenticate(request, username=data.email, password=data.password)
    
    if user is None:
        print(f"❌ Authentication failed for email: {data.email}")
        return api.create_response(
            request,
            {"detail": "No active account found with the given credentials"},
            status=401
        )
    
    print(f"✅ User authenticated: {user.email}")
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    
    print(f"Generated access token: {access_token[:20]}...")
    print(f"Generated refresh token: {refresh_token[:20]}...")
    
    # Prepare response data
    response_data = {
        'access': access_token,
        'refresh': refresh_token,
        **get_token_expiry_info(access_token, refresh_token)
    }
    
    # Create response with cookies
    response = api.create_response(request, response_data, status=200)
    add_token_cookies(response, access_token, refresh_token)
    
    return response


@api.post("/jwt/refresh/", response=RefreshResponseSchema, tags=["Authentication"])
def token_refresh(request, data: TokenRefreshSchema = None):
    """
    Refresh access token using refresh token from cookie or body
    """
    # Try to get refresh token from cookie first, then from body
    refresh_token = request.COOKIES.get('refresh')
    
    if not refresh_token and data:
        refresh_token = data.refresh
    
    if not refresh_token:
        return api.create_response(
            request,
            {"detail": "Refresh token not found"},
            status=401
        )
    
    try:
        # Generate new access token
        refresh = RefreshToken(refresh_token)
        access_token = str(refresh.access_token)
        
        # Prepare response data
        response_data = {
            'access': access_token,
            **get_token_expiry_info(access_token)
        }
        
        # Create response with new access token cookie
        response = api.create_response(request, response_data, status=200)
        add_token_cookies(response, access_token)
        
        return response
        
    except TokenError as e:
        return api.create_response(
            request,
            {"detail": str(e)},
            status=401
        )


@api.post("/jwt/verify/", tags=["Authentication"])
def token_verify(request, data: TokenVerifySchema = None):
    """
    Verify if access token is valid
    """
    # Try to get token from cookie first, then from body
    token = request.COOKIES.get('access')
    
    if not token and data:
        token = data.token
    
    if not token:
        return api.create_response(
            request,
            {"detail": "Token not found"},
            status=401
        )
    
    try:
        # Validate the token
        AccessToken(token)
        return {"detail": "Token is valid"}
        
    except TokenError as e:
        return api.create_response(
            request,
            {"detail": str(e)},
            status=401
        )


@api.post("/logout/", tags=["Authentication"])
def logout(request):
    """
    Logout - Clear authentication cookies
    """
    response = api.create_response(request, {"detail": "Successfully logged out"}, status=200)
    response.delete_cookie('access', path=settings.AUTH_COOKIE_PATH)
    response.delete_cookie('refresh', path=settings.AUTH_COOKIE_PATH)
    return response


# ============== PROTECTED ENDPOINTS ==============

@api.post("/todo/create/", auth=CustomJWTAuth(), tags=["ToDo"])
def create_todo(request, data: ToDoSchema):
    """
    Create a ToDo item (Protected endpoint - requires authentication)
    """
    print("=" * 50)
    print("CREATE TODO ENDPOINT")
    print("=" * 50)
    print(f"request.user: {request.user}")
    print(f"User type: {type(request.user)}")
    print(f"request.auth: {request.auth}")
    
    # Check if user is authenticated
    if not hasattr(request, 'auth') or request.auth is None:
        print("❌ No auth object found")
        return api.create_response(
            request,
            {"detail": "Authentication credentials were not provided"},
            status=401
        )
    
    # The authenticated user should be in request.auth (not request.user for custom auth)
    user = request.auth
    print(f"Authenticated user from request.auth: {user}")
    
    todo = ToDo.objects.create(
        title=data.title,
        description=data.description,
        completed=False,
        user=user
    )
    
    return {
        "message": "Todo item created successfully!",
        "todo_id": todo.id,
        "user": user.email
    }