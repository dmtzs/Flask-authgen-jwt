import os
is_github_action = os.getenv("GITHUB_ACTIONS", False)
import sys
if not is_github_action:
    sys.path.append("../src")
else:
    sys.path.append('src')
import unittest
from flask_authgen_jwt import Core, DecJwt, GenJwt

# Create a Flask-Authgen-JWT Core, DecJwt and GenJwt instance
# Crea una instancia de Flask-Authgen-JWT Core, DecJwt y GenJwt
core = Core()
auth = DecJwt()
auth_gen = GenJwt()

# Define a function that returns the user roles
# Define una función que retorna los roles del usuario
@core.get_user_roles
def get_user_roles(username: str) -> list[str]:
    return ["admin", "user", "guest", username]

@auth.verify_jwt_credentials
def verify_jwt_credentials(username_jwt: str, password_jwt: str) -> bool:
    if username_jwt == 'test' and password_jwt == 'test':
        return True
    return False

class TestFlaskAuthgenJwt(unittest.TestCase):
    def test_roles_by_username(self):
        # Generate a list of roles by username
        # Generar una lista de roles por nombre de usuario
        my_usr = "my_username"
        list_response = get_user_roles(my_usr)

        # Assert that the response is a list
        # Comprobar que la respuesta es una lista
        self.assertTrue(isinstance(list_response, list))

        # Assert that the list response all items are strings
        # Comprobar que todos los elementos de la lista son cadenas de texto
        self.assertTrue(all(isinstance(item, str) for item in list_response))

        # Assert that the list response all items are strings and that are four in the list
        # Comprobar que todos los elementos de la lista son cadenas de texto y que hay cuatro en la lista
        self.assertEqual(list(map(type, list_response)).count(str), 4)

    def test_jwt_credentials_auth(self):
        # Calling the authentication function with valid username and password
        # and check that returns True
        # Llamar a la función de autenticación con un nombre de usuario y
        # contraseña válidos y comprobar que devuelve True
        self.assertTrue(verify_jwt_credentials('test', 'test'))

        # Calling the authentication function with invalid username and password
        # and check that returns False
        # Llamar a la función de autenticación con un nombre de usuario y
        # contraseña inválidos y comprobar que devuelve False
        self.assertFalse(verify_jwt_credentials('wrong', 'wrong'))

if __name__ == '__main__':
    unittest.main()
