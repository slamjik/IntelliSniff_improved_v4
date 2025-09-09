from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex

COLUMNS = ['time', 'iface', 'src', 'dst', 'l4', 'sport', 'dport', 'len', 'class', 'info']

class PacketTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows = []

    def rowCount(self, parent=QModelIndex):
        return len(self._rows)

    def columnCount(self, parent=QModelIndex):
        return len(COLUMNS)

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index, role):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return str(row[index.column()])
        return None

    def append(self, row):
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def as_dicts(self):
        out = []
        for r in self._rows:
            out.append({'time': r[0], 'iface': r[1], 'src': r[2], 'dst': r[3], 'l4': r[4], 'sport': r[5], 'dport': r[6], 'len': r[7], 'class': r[8], 'info': r[9]})
        return out

    def trim_front(self, n=1000):
        if n <= 0:
            return
        self.beginResetModel()
        self._rows = self._rows[n:]
        self.endResetModel()
