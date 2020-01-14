import pyodbc
cnxn = pyodbc.connect('Driver={SQL Server};Trusted_Connection=yes;Server=localhost;database=msdb')
c = cnxn.cursor()
q = 'select top 11 name, create_date from sys.databases order by create_date desc'
c.execute(q)
for r in c:
    name, create_date = r
    print name, ',', create_date
