class Project:
    """
    Modèle représentant un projet/pentest auquel appartiennent des scans.
    """

    def __init__(self, project_id, name, description=None, created_at=None):
        self.id = project_id
        self.name = name
        self.description = description
        self.created_at = created_at

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at
        }

    def __repr__(self):
        return f"<Project id={self.id} name='{self.name}'>"
