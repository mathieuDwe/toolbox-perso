class Scan:
    """
    Modèle métier représentant un résultat de scan.
    """

    def __init__(self, scan_type, data, timestamp=None, user=None, filename=None):
        self.scan_type = scan_type
        self.data = data
        self.timestamp = timestamp
        self.user = user
        self.filename = filename

    def to_dict(self):
        return {
            "scan_type": self.scan_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "user": self.user,
            "filename": self.filename
        }

    def __repr__(self):
        return f"<Scan type={self.scan_type} filename={self.filename}>"
