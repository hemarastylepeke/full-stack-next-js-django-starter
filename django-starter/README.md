# Django Rest Framework Starter with Custom User Model and Djoser Authentication

#### This starter code provides a Django Rest Framework setup with a custom user model and authentication endpoints using Djoser. It's designed to jumpstart your Django API development with robust user management features.

## Features

- Custom user model for flexibility in user data storage.
- Authentication endpoints provided by Djoser and jwt for user registration, login, logout, password reset, and more.
- JWT authentication for secure API access.
- Easy integration with existing Django projects or as a standalone API.


## Installation

- git clone https://github.com/hemarastylepeke/django-backend-starter.git
- pip install -r requirements.txt
- python manage.py migrate
- python manage.py runserver

## Endpoints

- User Registration: POST /api/auth/users/
- JWT Token Creation: POST /api/auth/jwt/create/
- User Activation: POST /api/auth/users/activation/
- JWT Token Refresh: POST /api/auth/jwt/refresh/
- JWT Token Verification: POST /api/auth/jwt/verify/
- User Profile Details: GET /api/auth/users/me/
- Password Reset Request: POST /api/auth/users/reset_password/
- Password Reset Confirmation: POST /api/auth/users/reset_password_confirm/
- User Logout: POST /api/auth/logout/


##Usage
You can now start using the provided API endpoints for user management and authentication. Use tools like Postman or curl to interact with the API.

For detailed documentation on Djoser endpoints and configurations, refer to the [Djoser Documentation](https://djoser.readthedocs.io/).

Contributing
Contributions are welcome! Feel free to open issues or submit pull requests for any improvements or additional features you'd like to see.

License
This project is licensed under the [MIT License](https://opensource.org/license/mit).
