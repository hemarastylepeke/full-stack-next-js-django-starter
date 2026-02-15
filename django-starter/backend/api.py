from ninja import NinjaAPI, Schema
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
        
        # Try Authorization header first
        auth_header = request.headers.get('Authorization', '')
        
        token = None
        
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Fallback to cookie
        if not token:
            token = request.COOKIES.get('access')
        
        if not token:
            return None
        
        try:
            # Validate the token
            access_token = AccessToken(token)
            
            user_id = access_token.get('user_id')
            
            if not user_id:
                return None
            
            # Get user from database
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)
            return user
            
        except TokenError as e:
            return None
        except InvalidToken as e:
            return None
        except User.DoesNotExist:
            return None
        except Exception as e:
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
        return api.create_response(
            request,
            {"detail": "No active account found with the given credentials"},
            status=401
        )
    
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token = str(refresh)
    
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

# Create a TO DO Item
@api.post("/todo/create/", auth=CustomJWTAuth(), tags=["ToDo"])
def create_todo(request, data: ToDoSchema):
    
    # Check if user is authenticated
    if not hasattr(request, 'auth') or request.auth is None:
        return api.create_response(
            request,
            {"detail": "Authentication credentials were not provided"},
            status=401
        )
    
    # The authenticated user should be in request.auth
    user = request.auth
    
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

# Get a list of all TO DO items for the authenticated user
@api.get("/todo/list/", auth=CustomJWTAuth(), tags=["ToDo"])
def list_todos(request):
    # Check if user is authenticated
    if not hasattr(request, 'auth') or request.auth is None:
        return api.create_response(
            request,
            {"detail": "Authentication credentials were not provided"},
            status=401
        )
    
    # The authenticated user should be in request.auth
    user = request.auth

    # Get all ToDo items for this user
    todos = ToDo.objects.filter(user=user)
    return {
        "todos": [
            {
                "id": todo.id,
                "title": todo.title,
                "description": todo.description,
                "completed": todo.completed
            }
            for todo in todos
        ]
    }

# Edit a TO DO item
@api.put("/todo/edit/{todo_id}/", auth=CustomJWTAuth(), tags=["ToDo"])
def edit_todo(request, todo_id: int, data: ToDoSchema):
    # Check if user is authenticated
    if not hasattr(request, 'auth') or request.auth is None:
        return api.create_response(
            request,
            {"detail": "Authentication credentials were not provided"},
            status=401
        )
    
    # The authenticated user should be in request.auth
    user = request.auth

    try:
        todo = ToDo.objects.get(id=todo_id, user=user)
        todo.title = data.title
        todo.description = data.description
        todo.completed = data.completed
        todo.save()
        
        return {
            "message": "Todo item updated successfully!",
            "todo_id": todo.id
        }
        
    except ToDo.DoesNotExist:
        return api.create_response(
            request,
            {"detail": "Todo item not found"},
            status=404
        )
    
# Delete a TO DO item
@api.delete("/todo/delete/{todo_id}/", auth=CustomJWTAuth(), tags=["ToDo"])
def delete_todo(request, todo_id: int):
    # Check if user is authenticated
    if not hasattr(request, 'auth') or request.auth is None:
        return api.create_response(
            request,
            {"detail": "Authentication credentials were not provided"},
            status=401
        )
    
    # The authenticated user should be in request.auth
    user = request.auth

    try:
        todo = ToDo.objects.get(id=todo_id, user=user)
        todo.delete()
        
        return {
            "message": "Todo item deleted successfully!",
            "todo_id": todo_id
        }
        
    except ToDo.DoesNotExist:
        return api.create_response(
            request,
            {"detail": "Todo item not found"},
            status=404
        )