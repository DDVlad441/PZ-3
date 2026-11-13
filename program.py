import hashlib


class User:

    def __init__(self, username, password, access_level=1):
        self.username = username

        # Зберігаємо хеш пароля
        self._password_hash = self._hash(password)
        self.access_level = access_level

    @staticmethod
    def _hash(password):
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def check_password(self, password):
        """Перевіряє, чи збігається введений пароль зі збереженим."""
        return self._hash(password) == self._password_hash

    def __str__(self):
        return f"{self.__class__.__name__}(username={self.username!r}, level={self.access_level})"


class Guest(User):
    """Гість — мінімальний рівень доступу."""

    def __init__(self, username, password):
        super().__init__(username, password, access_level=1)


class RegularUser(User):
    """Звичайний користувач — середній рівень доступу."""

    def __init__(self, username, password):
        super().__init__(username, password, access_level=2)


class Admin(User):
    """Адміністратор — найвищий рівень доступу."""

    def __init__(self, username, password):
        super().__init__(username, password, access_level=3)


class AccessControl:
    """Контроль доступу: зберігає користувачів та виконує автентифікацію."""

    def __init__(self):
        # Ключ — ім'я користувача, значення — об'єкт користувача
        self.users = {}

    def add_user(self, user):
        """Додає нового користувача до системи."""
        if user.username in self.users:
            print(f"Користувач '{user.username}' уже існує.")
            return False

        self.users[user.username] = user
        return True

    def authenticate_user(self, username, password):
        """
        Перевіряє існування користувача та правильність пароля.
        Повертає об'єкт користувача при успіху, інакше None.
        """
        user = self.users.get(username)

        if user is not None and user.check_password(password):
            return user

        return None


if __name__ == "__main__":

    system = AccessControl()

    system.add_user(Admin("admin", "admin123"))
    system.add_user(RegularUser("ivan", "qwerty"))
    system.add_user(Guest("guest", "guest"))

    # Успішна автентифікація
    user = system.authenticate_user("ivan", "qwerty")
    print(user if user else "Невдача")

    # Неправильний пароль
    user = system.authenticate_user("ivan", "wrong")
    print(user if user else "Невдача")

    # Неіснуючий користувач
    user = system.authenticate_user("petro", "123")
    print(user if user else "Невдача")