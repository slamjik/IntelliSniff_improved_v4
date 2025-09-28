from traffic_analyzer.storage import storage
def test_insert_and_recent():
    storage.insert_flow({'src':'1.1.1.1','dst':'2.2.2.2','sport':123,'dport':80,'proto':'TCP','packets':1,'bytes':100,'label':'web','ts':1234567890000})
    rows = storage.recent(limit=1)
    assert len(rows) >= 1
