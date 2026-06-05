class User:
    """
    Modèle métier User (pas lié à SQLAlchemy).
    Permet de structurer clairement les données d'un utilisateur.
    """

    def __init__(self, user_id, username, role, created_at=None):
        self.id = user_id
        self.username = username
        self.role = role
        self.created_at = created_at

    def to_dict(self):
        """Retourne une version JSON-friendly du User."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at
        }

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
