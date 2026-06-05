class Role:
    """
    Modèle simple pour représenter un rôle utilisateur.
    """
    def __init__(self, name):
        self.name = name

    def to_dict(self):
        return {"role": self.name}

    def __repr__(self):
        return f"<Role {self.name}>"
