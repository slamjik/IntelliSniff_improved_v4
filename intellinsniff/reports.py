import pandas as pd

class ReportManager:
    def export_csv(self, packets, filename="report.csv"):
        df = pd.DataFrame(packets)
        df.to_csv(filename, index=False)
